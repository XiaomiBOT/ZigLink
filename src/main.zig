const std = @import("std");
const net = std.net;
const http = std.http;
const sysinfo = @import("utils/sysinfo.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

const DB_FILE = "database.json";

// Data Structure (Updated with delete_token)
const LinkData = struct {
    url: []const u8,
    timestamp: i64,
    clicks: u64 = 0,
    expires_at: i64 = 0,
    password: ?[]const u8 = null,
    token: ?[]const u8 = null, // Secret token to delete this link
};

// Entry for JSON Serialization
const LinkEntry = struct {
    code: []const u8,
    url: []const u8,
    timestamp: i64,
    clicks: u64,
    expires_at: i64,
    password: ?[]const u8,
    token: ?[]const u8 = null,
};

var db: std.StringHashMap(LinkData) = undefined;

pub fn main() !void {
    db = std.StringHashMap(LinkData).init(allocator);
    defer db.deinit();

    try loadDB();

    const loopback = try net.Address.parseIp4("0.0.0.0", 8081);
    var server = try loopback.listen(.{ .reuse_address = true });
    defer server.deinit();

    std.debug.print("ZigLink Server Running on Port 8081\n", .{});

    while (true) {
        const connection = try server.accept();
        defer connection.stream.close();

        var buffer: [8192]u8 = undefined;
        const size = try connection.stream.read(&buffer);
        if (size == 0) continue;
        const request_text = buffer[0..size];

        if (isBot(request_text)) {
            try respond(connection.stream, 403, "application/json", "{\"error\": \"you can't because you're robot!\"}");
            continue;
        }

        var iter = std.mem.tokenizeAny(u8, request_text, " \r\n");
        const method = iter.next() orelse continue;
        const path_full = iter.next() orelse continue;

        var path = path_full;
        var query: ?[]const u8 = null;
        if (std.mem.indexOf(u8, path_full, "?")) |idx| {
            path = path_full[0..idx];
            query = path_full[idx+1..];
        }

        if (std.mem.eql(u8, path, "/auth/verify") and std.mem.eql(u8, method, "POST")) {
            try serveAuthCookie(connection.stream);
            continue;
        }

        // Routing
        if (std.mem.eql(u8, path, "/") or std.mem.eql(u8, path, "/index.html")) {
            try serveFile(connection.stream, "src/static/index.html");
        }
        else if (std.mem.eql(u8, path, "/og-image.png")) {
            try serveImage(connection.stream, "src/static/og-image.png", "image/png");
        }
        else if (std.mem.eql(u8, path, "/favicon.svg")) {
            try serveImage(connection.stream, "src/static/favicon.svg", "image/svg+xml");
        }
        else if (std.mem.eql(u8, path, "/info")) {
            try serveJsonStats(connection.stream);
        }
        else if (std.mem.eql(u8, path, "/api/shorten") and std.mem.eql(u8, method, "POST")) {
            if (std.mem.indexOf(u8, request_text, "\r\n\r\n")) |body_start| {
                const body = request_text[body_start + 4 ..];
                try handleShorten(connection.stream, body);
            }
        }
        else if (std.mem.startsWith(u8, path, "/api/stats/")) {
            const code = path[11..];
            try handleGetStats(connection.stream, code);
        }
        // DELETE API
        else if (std.mem.startsWith(u8, path, "/api/delete/") and std.mem.eql(u8, method, "DELETE")) {
            const code = path[12..];
            if (std.mem.indexOf(u8, request_text, "\r\n\r\n")) |body_start| {
                const body = request_text[body_start + 4 ..];
                try handleDelete(connection.stream, code, body);
            }
        }
        // Redirect
        else {
            if (path.len > 1) {
                const code = path[1..]; 
                if (db.getPtr(code)) |data| {
                    try handleRedirectFlow(connection.stream, data, query);
                } else {
                    try serveFile(connection.stream, "src/static/404.html");
                }
            } else {
                try serveFile(connection.stream, "src/static/404.html");
            }
        }
    }
}

fn handleRedirectFlow(stream: net.Stream, data: *LinkData, query: ?[]const u8) !void {
    const now = std.time.timestamp();
    if (data.expires_at > 0 and now > data.expires_at) {
        try respond(stream, 410, "text/html", "<h1>Link Expired</h1><p>This link is no longer available.</p>");
        return;
    }
    if (data.password) |pass| {
        var provided_pass: ?[]const u8 = null;
        if (query) |q| {
            if (std.mem.indexOf(u8, q, "pwd=")) |idx| {
                provided_pass = q[idx+4..];
                if (std.mem.indexOf(u8, provided_pass.?, "&")) |end| {
                    provided_pass = provided_pass.?[0..end];
                }
            }
        }
        if (provided_pass == null or !std.mem.eql(u8, provided_pass.?, pass)) {
            try serveFile(stream, "src/static/password.html");
            return;
        }
    }
        data.clicks += 1;
        saveDB() catch {}; 
    
        // Use 302 Found (Temporary Redirect) instead of 301 to prevent browser caching
        // This ensures that password and expiry checks are always executed on the server.
        const response = try std.fmt.allocPrint(allocator, "HTTP/1.1 302 Found\r\nLocation: {s}\r\nCache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\nExpires: 0\r\n\r\n", .{data.url});
        defer allocator.free(response);
        try stream.writeAll(response);
    }
    
    fn handleShorten(stream: net.Stream, body: []const u8) !void {
    const ParsedBody = struct {
        url: []const u8,
        alias: ?[]const u8 = null,
        password: ?[]const u8 = null,
        ttl: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(ParsedBody, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        try respond(stream, 400, "application/json", "{\"error\":\"Invalid JSON\"}");
        return;
    };
    defer parsed.deinit();
    const req = parsed.value;

    if (req.url.len == 0 or std.mem.indexOf(u8, req.url, " ") != null or (!std.mem.startsWith(u8, req.url, "http://") and !std.mem.startsWith(u8, req.url, "https://"))) {
        try respond(stream, 403, "application/json", "{\"error\":\"Invalid URL format\"}");
        return;
    }

    var expires_at: i64 = 0;
    if (req.ttl) |ttl_str| {
        if (std.fmt.parseInt(i64, ttl_str, 10)) |mins| {
            if (mins > 0) expires_at = std.time.timestamp() + (mins * 60);
        } else |_| {} 
    }

    var password_copy: ?[]const u8 = null;
    if (req.password) |p| {
        if (p.len > 0) password_copy = try allocator.dupe(u8, p);
    }

    var code: []const u8 = undefined;
    if (req.alias) |alias_raw| {
        if (alias_raw.len > 0) {
            const alias = try slugify(allocator, alias_raw);
            if (db.contains(alias)) {
                allocator.free(alias);
                if (password_copy) |p| allocator.free(p);
                try respond(stream, 409, "application/json", "{\"error\":\"Alias taken\"}");
                return;
            }
            code = alias;
        } else {
            code = try generateCode();
        }
    } else {
        code = try generateCode();
    }

    // Generate DELETE TOKEN
    const del_token = try generateCode(); // 6 chars random string as token

    const new_data = LinkData{
        .url = try allocator.dupe(u8, req.url),
        .timestamp = std.time.timestamp(),
        .clicks = 0,
        .expires_at = expires_at,
        .password = password_copy,
        .token = del_token
    };
    try db.put(code, new_data);
    saveDB() catch {};

    const response = try std.fmt.allocPrint(allocator, 
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n{{\"short_code\": \"{s}\", \"delete_token\": \"{s}\"}}", 
        .{code, del_token});
    defer allocator.free(response);
    try stream.writeAll(response);
}

fn handleDelete(stream: net.Stream, code: []const u8, body: []const u8) !void {
    const ParsedBody = struct { token: []const u8 };
    const parsed = std.json.parseFromSlice(ParsedBody, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        try respond(stream, 400, "application/json", "{\"error\":\"Missing token\"}");
        return;
    };
    defer parsed.deinit();
    
    if (db.getPtr(code)) |data| {
        if (data.token) |t| {
            if (std.mem.eql(u8, t, parsed.value.token)) {
                // TOKEN MATCHES, DELETE!
                _ = db.remove(code);
                saveDB() catch {};
                try respond(stream, 200, "application/json", "{\"status\":\"deleted\"}");
                return;
            }
        }
    }
    
    try respond(stream, 403, "application/json", "{\"error\":\"Invalid token or link not found\"}");
}

fn handleGetStats(stream: net.Stream, code: []const u8) !void {
    if (db.get(code)) |data| {
        const resp = try std.fmt.allocPrint(allocator, 
            "{{\"code\":\"{s}\",\"url\":\"{s}\",\"clicks\":{d},\"created\":{d},\"expires\":{d},\"protected\":{}}}", 
            .{code, data.url, data.clicks, data.timestamp, data.expires_at, data.password != null});
        defer allocator.free(resp);
        try respond(stream, 200, "application/json", resp);
    } else {
        try respond(stream, 404, "application/json", "{\"error\":\"Link not found\"}");
    }
}

// Helpers
fn respond(stream: net.Stream, code: u16, ctype: []const u8, body: []const u8) !void {
    const status = switch(code) { 200=>"OK", 301=>"Moved Permanently", 400=>"Bad Request", 403=>"Forbidden", 404=>"Not Found", 409=>"Conflict", 410=>"Gone", else=>"Error" };
    const header = try std.fmt.allocPrint(allocator, "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n", .{code, status, ctype});
    defer allocator.free(header);
    try stream.writeAll(header);
    try stream.writeAll(body);
}

fn isBot(request: []const u8) bool {
    if (std.mem.indexOf(u8, request, "User-Agent: ")) |idx| {
        const start = idx + 12;
        const end = std.mem.indexOfPos(u8, request, start, "\r\n") orelse request.len;
        const ua = request[start..end];
        const bots = [_][]const u8{"curl", "wget", "python", "axios", "Go-http", "Java"};
        for (bots) |b| { if (std.mem.indexOf(u8, ua, b) != null) return true; }
    }
    return false;
}

fn serveAuthCookie(stream: net.Stream) !void {
    try stream.writeAll("HTTP/1.1 200 OK\r\nSet-Cookie: zig_guard=passed; Path=/; HttpOnly; Max-Age=86400\r\n\r\nOK");
}

fn loadDB() !void {
    const file = std.fs.cwd().openFile(DB_FILE, .{}) catch return;
    defer file.close();
    const stat = try file.stat();
    if (stat.size == 0) return;
    const content = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(content);
    const parsed = try std.json.parseFromSlice([]LinkEntry, allocator, content, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    for (parsed.value) |item| {
        const key = try allocator.dupe(u8, item.code);
        var pass: ?[]const u8 = null;
        if (item.password) |p| pass = try allocator.dupe(u8, p);
        var tok: ?[]const u8 = null;
        if (item.token) |t| tok = try allocator.dupe(u8, t);
        const val = LinkData{ .url = try allocator.dupe(u8, item.url), .timestamp = item.timestamp, .clicks = item.clicks, .expires_at = item.expires_at, .password = pass, .token = tok };
        try db.put(key, val);
    }
}

fn saveDB() !void {
    const file = try std.fs.cwd().createFile(DB_FILE, .{});
    defer file.close();
    var list = std.ArrayList(LinkEntry).init(allocator);
    defer list.deinit();
    var iter = db.iterator();
    while (iter.next()) |entry| {
        try list.append(LinkEntry{ .code = entry.key_ptr.*, .url = entry.value_ptr.url, .timestamp = entry.value_ptr.timestamp, .clicks = entry.value_ptr.clicks, .expires_at = entry.value_ptr.expires_at, .password = entry.value_ptr.password, .token = entry.value_ptr.token });
    }
    try std.json.stringify(list.items, .{ .whitespace = .indent_2 }, file.writer());
}

fn serveFile(stream: net.Stream, path: []const u8) !void {
    const file = std.fs.cwd().openFile(path, .{}) catch { try respond(stream, 404, "text/plain", "Not Found"); return; };
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(content);
    try respond(stream, 200, "text/html", content);
}

fn serveImage(stream: net.Stream, path: []const u8, mime: []const u8) !void {
    const file = std.fs.cwd().openFile(path, .{}) catch { try respond(stream, 404, "text/plain", "Not Found"); return; };
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 5 * 1024 * 1024);
    defer allocator.free(content);
    try respond(stream, 200, mime, content);
}

fn serveJsonStats(stream: net.Stream) !void {
    const info = sysinfo.collect(allocator) catch sysinfo.SystemInfo{ .distro="Unknown", .kernel="-", .arch="-", .hostname="-", .cpu_model="-", .cpu_cores=0, .ram_total_mb=0, .ram_free_mb=0, .uptime_sec=0, .user="-" };
    const body = try std.fmt.allocPrint(allocator, "{{\"status\":\"online\",\"total_links\":{d}, \"os_cpu\":\"{s}\"}}", .{db.count(), info.cpu_model});
    defer allocator.free(body);
    try respond(stream, 200, "application/json", body);
}

fn slugify(alloc: std.mem.Allocator, input: []const u8) ![]const u8 {
    const res = try alloc.dupe(u8, input);
    for (res) |*c| { if (c.* == ' ' or c.* == '/' or c.* == '\\') c.* = '-'; }
    return res;
}

fn generateCode() ![]const u8 {
    const charset = "abcdefghijklmnopqrstuvwxyz0123456789";
    var code = try allocator.alloc(u8, 6);
    for (0..6) |i| { code[i] = charset[std.crypto.random.intRangeAtMost(usize, 0, charset.len - 1)]; }
    return code;
}
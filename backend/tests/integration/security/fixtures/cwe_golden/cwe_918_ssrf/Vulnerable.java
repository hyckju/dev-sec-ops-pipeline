// CWE-918: Server-Side Request Forgery — 의도적 취약 픽스처
// p/java 룰팩 (ssrf / tainted-url 키워드) 탐지 대상

package com.example.vulnerable;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;

public class Vulnerable {

    public String fetchRemote(HttpServletRequest req) throws IOException {
        String url = req.getParameter("url");
        // ruleid: tainted-url-fetch
        URL u = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        InputStream is = conn.getInputStream();
        byte[] bytes = is.readAllBytes();
        is.close();
        return new String(bytes);
    }

    public String proxy(HttpServletRequest req) throws IOException {
        String target = req.getParameter("target");
        // ruleid: tainted-url-fetch
        URL u = new URL("https://api.internal/" + target);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestMethod("GET");
        return new String(conn.getInputStream().readAllBytes());
    }

    public byte[] webhook(HttpServletRequest req) throws IOException {
        String callback = req.getParameter("callback_url");
        // ruleid: tainted-url-fetch
        URL u = new URL(callback);
        return u.openStream().readAllBytes();
    }
}

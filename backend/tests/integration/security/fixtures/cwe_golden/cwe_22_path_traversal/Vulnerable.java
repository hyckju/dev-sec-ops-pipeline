// CWE-22: Path Traversal — 의도적 취약 픽스처
// p/java 룰팩 (tainted-file / httpservlet-path 키워드) 탐지 대상

package com.example.vulnerable;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Vulnerable {

    public void downloadFile(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        String filename = req.getParameter("file");
        // ruleid: tainted-file-path
        File f = new File("/var/data/" + filename);
        FileInputStream fis = new FileInputStream(f);
        resp.getOutputStream().write(fis.readAllBytes());
        fis.close();
    }

    public String readConfig(HttpServletRequest req) throws IOException {
        String configName = req.getParameter("config");
        // ruleid: tainted-file-path
        FileInputStream fis = new FileInputStream("/etc/app/" + configName);
        byte[] bytes = fis.readAllBytes();
        fis.close();
        return new String(bytes);
    }

    public void deleteUserFile(HttpServletRequest req) {
        String userFile = req.getParameter("name");
        // ruleid: tainted-file-path
        File toDelete = new File("/uploads/" + userFile);
        toDelete.delete();
    }
}

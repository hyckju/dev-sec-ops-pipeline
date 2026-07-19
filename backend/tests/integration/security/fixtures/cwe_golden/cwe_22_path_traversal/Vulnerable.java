// CWE-22: Path Traversal — 의도적 취약 픽스처
// p/java 룰팩 (tainted-file / httpservlet-path 키워드) 탐지 대상

package com.example.vulnerable;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class Vulnerable {

    // 주의: 여기서 HttpServletResponse에 바이트를 직접 write하면 p/java의 일반 XSS
    // 감사 룰(no-direct-response-writer)이 부수적으로 함께 발화해 CWE-22 픽스처가
    // CWE-79로 오분류된다. Path Traversal 탐지엔 아래 File 생성 줄만 필요하므로
    // 응답 스트림에는 쓰지 않는다.
    public byte[] downloadFile(HttpServletRequest req) throws IOException {
        String filename = req.getParameter("file");
        // ruleid: tainted-file-path
        File f = new File("/var/data/" + filename);
        FileInputStream fis = new FileInputStream(f);
        byte[] bytes = fis.readAllBytes();
        fis.close();
        return bytes;
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

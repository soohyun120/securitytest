package com.example.securitytest.mail;

import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;

@Service
@RequiredArgsConstructor
public class MailSendService {

    private final JavaMailSender javaMailSender;

    /**
     * 회원가입 인증 메일 전송
     */
    public void sendMail(String email, String authToken) {
        try {
            MailUtils sendMail = new MailUtils(javaMailSender);
            sendMail.setSubject("인하대학교 이메일 인증");
            sendMail.setText(new StringBuffer().append("<h1>[이메일 인증]</h1>")
                    .append("<p>아래 링크를 클릭하시면 이메일 인증이 완료됩니다.</p>")
                    .append("<a href='http://localhost:8080/api/user/joinConfirm?email=")
                    .append(email)
                    .append("&authToken=")
                    .append(authToken)
                    .append("' target='_blenk'>이메일 인증 확인</a>")
                    .toString());
            sendMail.setFrom("suhyun12090@gmail.com", "관리자");
            sendMail.setTo(email);
            sendMail.send();

        } catch (MessagingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    /**
     * 비밀번호 찾기 인증 메일 전송
     */
    public void sendMail_pw(String email, String tempPassword) {
        try {
            MailUtils sendMail = new MailUtils(javaMailSender);
            sendMail.setSubject("임시 비밀번호 안내 이메일입니다.");
            sendMail.setText(new StringBuffer().append("<h1>[임시 비밀번호]</h1>")
                    .append(email + "님의 임시 비밀번호는 " + tempPassword + "입니다."
                    + "로그인 후에 비밀번호를 반드시 변경 해주세요.")
                    .toString());
            sendMail.setFrom("suhyun12090@gmail.com", "관리자");
            sendMail.setTo(email);
            sendMail.send();

        } catch (MessagingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

}

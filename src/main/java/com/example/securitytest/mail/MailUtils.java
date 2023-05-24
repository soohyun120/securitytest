package com.example.securitytest.mail;

import jakarta.activation.DataSource;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;

import java.io.UnsupportedEncodingException;

public class MailUtils {

    private JavaMailSender javaMailSender;
    private MimeMessage message;
    private MimeMessageHelper messageHelper;

    public MailUtils(JavaMailSender javaMailSender) throws MessagingException {
        this.javaMailSender = javaMailSender;
        this.message = javaMailSender.createMimeMessage();
        this.messageHelper = new MimeMessageHelper(message, true, "UTF-8");
    }

    public void setSubject(String subject) throws MessagingException {
        messageHelper.setSubject(subject);
    }

    public void setText(String htmlContent) throws MessagingException {
        messageHelper.setText(htmlContent, true);
    }

    public void setFrom(String email, String name) throws MessagingException, UnsupportedEncodingException {
        messageHelper.setFrom(email, name);
    }

    public void setTo(String email) throws MessagingException {
        messageHelper.setTo(email);
    }

    public void addInline(String contentId, DataSource dataSource) throws MessagingException{
        messageHelper.addInline(contentId, dataSource);
    }

    public void send() {
        javaMailSender.send(message);
    }
}

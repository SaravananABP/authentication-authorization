package validation.Authentication.Service;

import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import validation.Authentication.Pojo.OTP;
import validation.Authentication.Repository.OTPRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class VerificationService {
    @Autowired
    private JavaMailSender mailSender;
    @Autowired
    private OTPRepository otpRepository;

    @Value("email.expire.timeout")
    private Integer expireTime ;
    @Value("email.otp.length ")
    private Integer otpLength;
    @Value("email.subject")
    private String emailSub;
    private static final SecureRandom random = new SecureRandom();

    public String sendOTP(String toEmail,String otp) {
        SimpleMailMessage message = new SimpleMailMessage();

        message.setTo(toEmail);
        message.setSubject(emailSub);
        message.setText("Your OTP is: " + otp + ". It is valid for 5 minutes.");

        mailSender.send(message);
        return "OTP sent successfully to " + toEmail;
    }
    public static String generateOTP(int length) {
        String digits = "0123456789";
        StringBuilder otp = new StringBuilder();

        for (int i = 0; i < length; i++) {
            otp.append(digits.charAt(random.nextInt(digits.length())));
        }

        return otp.toString();
    }

    @Transactional
    public String generateAndSendOTP(String email) {
        String otp = generateOTP(otpLength);
        LocalDateTime expirationTime = LocalDateTime.now().plusMinutes(expireTime);

        // Save OTP to DB
        OTP otpRecord = new OTP(email, otp, expirationTime);
        if(otpRepository.findByEmail(email)!=null) {
            otpRepository.save(otpRecord);
        }else{
            otpRepository.updateOtp(otp,expirationTime,email);
        }

        // Send OTP via Email
        sendOTP(email,otp);

        return "OTP sent successfully to " + email;
    }

    public String validateOTP(String email, String otp) {
        Optional<OTP> otpRecord = otpRepository.findByEmail(email);
//        System.out.println("**********************"+otpRecord.get().getExpirationTime());

        if (otpRecord.isPresent()) {
            OTP storedOTP = otpRecord.get();

            if (storedOTP.getExpirationTime().isBefore(LocalDateTime.now())) {
                return "OTP has expired. Request a new one.";
            }
            if (!storedOTP.getOtp().equals(otp)) {
                return "Invalid OTP. Please try again.";
            }
            updateOTPStatus(email,true);
            return "OTP verification successful!";
        }
        return "No OTP found for this email.";
    }
    @Transactional // Ensure transactional context
    public void updateOTPStatus(String email, boolean valid) {

        otpRepository.updateStatus(valid,email);
    }

}

package validation.Authentication.Pojo;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Table(name = "otp_records")
@Data
public class OTP {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String email;
    private String otp;
    private LocalDateTime expirationTime;
    @Column(name = "verifyotp")
    private boolean verifyotp = false;
    public OTP(String email, String otp, LocalDateTime expirationTime) {
        this.email = email;
        this.otp = otp;
        this.expirationTime = expirationTime;
        this.verifyotp=false;
    }
    public OTP(){}

}


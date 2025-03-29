package validation.Authentication.Repository;

import jakarta.transaction.Transactional;
import validation.Authentication.Pojo.OTP;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

import java.util.Optional;

@Repository
public interface OTPRepository extends JpaRepository<OTP, Long> {
    Optional<OTP> findByEmail(String email);

    @Modifying
    @Transactional
    @Query("UPDATE OTP u SET u.otp = :gOtp, u.expirationTime = :expireTime WHERE u.email = :emailId")
    void updateOtp(String gOtp, LocalDateTime expireTime, String emailId);

    @Modifying
    @Transactional
    @Query("UPDATE OTP u SET u.verifyotp =:valid WHERE u.email = :emailId")
    void updateStatus(boolean valid, String emailId);

}

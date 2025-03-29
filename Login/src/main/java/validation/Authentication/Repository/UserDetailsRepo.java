package validation.Authentication.Repository;

import jakarta.transaction.Transactional;
import validation.Authentication.Pojo.UserDetailsInfo;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.JpaRepository;

@Repository
public interface UserDetailsRepo extends JpaRepository<UserDetailsInfo, Long> {

    UserDetailsInfo findByUserName(String name);
    UserDetailsInfo findByEmailId(String emailId);

    @Modifying
    @Transactional
    @Query("UPDATE UserDetailsInfo u SET u.role = :role WHERE u.emailId = :emailId")
    void updateRole(@Param("emailId") String emailId, @Param("role") String role);

    @Modifying
    @Transactional
    @Query("UPDATE UserDetailsInfo u SET u.password = :password WHERE u.emailId = :emailId")
    void UpdateUserPassword(@Param("emailId") String emailId, @Param("password") String password);
}

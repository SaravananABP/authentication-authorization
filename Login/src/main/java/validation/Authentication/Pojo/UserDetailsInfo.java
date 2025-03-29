package validation.Authentication.Pojo;

import jakarta.transaction.Transactional;
import lombok.Data;
import lombok.Getter;

import jakarta.persistence.*;

@Entity
@Table(name = "users_info")
@Data
public class UserDetailsInfo {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;


    @Column(unique = true, nullable = false,name = "userName")
    private String userName;

    @Column(unique = true, nullable = false,name = "password")
    private String password;

    @Column(name = "role")
    private String role;

//    @Property(name = "dateOfBirth")
////    private LocalDate DoB;
//    private String DoB;

    @Column( nullable = false,name = "Address")
    private String address;

    @Column(unique = true, nullable = true,name = "contactNo")
    private Long mobileNo;

    @Column(unique = true, nullable = false,name = "emailId")
    private String emailId;

    private  String DateOfbirth;




}

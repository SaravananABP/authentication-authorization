package validation.Authentication.Pojo;

import lombok.Data;

@Data
public class UpdatePassword {
    private String emailId;
    private String password;
    private String conformPassword;
}

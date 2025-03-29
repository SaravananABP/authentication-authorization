package validation.Authentication.Service;


import validation.Authentication.Pojo.UserDetailsInfo;
import validation.Authentication.Repository.UserDetailsRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;




@Component
public class UserDataService {

    @Autowired
    private UserDetailsRepo userDetailsRepo;

    public String changeRole(String emailid, String role) {
        UserDetailsInfo userDetails = userDetailsRepo.findByEmailId(emailid);
//                .orElseThrow(() -> new RuntimeException("ID is not found: " + emailid));
        if(userDetails.equals(null)){
            new RuntimeException("ID is not found: " + emailid);
        }
        userDetails.setRole(role.toUpperCase());
        userDetailsRepo.updateRole(emailid, role);
        return "Role updated successfully";
    }


}

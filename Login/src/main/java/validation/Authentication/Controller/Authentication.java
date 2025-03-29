package validation.Authentication.Controller;


import validation.Authentication.Pojo.AuthRequest;
import validation.Authentication.Pojo.UpdatePassword;
import validation.Authentication.Pojo.UserDetailsInfo;
import validation.Authentication.Repository.UserDetailsRepo;
import validation.Authentication.Service.JwtService;
import jakarta.websocket.server.PathParam;

import validation.Authentication.Service.UserInfoDetailsService;
import validation.Authentication.Service.VerificationService;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/auth")
public class Authentication {
    @Autowired
    UserDetailsRepo userDetailsRepo;
    @Autowired
    JwtService jwtService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private VerificationService verification;
    @Autowired
    private UserInfoDetailsService userDetailsService;




    @PostMapping("/create/newUser")
    public JSONObject createNewUser(@RequestBody UserDetailsInfo userDetailsInfo) {
        String regexPassword = "^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d@$!%*?&]{4,}$";
        String regexMail = "^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$";
        String regexMobileNo = "^[0-9]{10}$"; // 10-digit number

        Pattern passwordPattern = Pattern.compile(regexPassword);
        Pattern mailPattern = Pattern.compile(regexMail);
        Pattern mobileNoPattern = Pattern.compile(regexMobileNo);

        JSONObject response = new JSONObject();

        if (userDetailsRepo.findByUserName(userDetailsInfo.getUserName()) == null) {
            if (!passwordPattern.matcher(userDetailsInfo.getPassword()).matches()) {
                response.put("status", "Invalid password !!!");
                response.put("password", "Make a strong password");
                response.put("match_with", "Minimum length 8, at least 1 letter (uppercase, lowercase), and a special character");
                response.put("SamplePassword", "Qwerty@123");
            } else if (!mailPattern.matcher(userDetailsInfo.getEmailId()).matches()) {
                response.put("status", "Invalid email address !!!");
            } else if (!mobileNoPattern.matcher(String.valueOf(userDetailsInfo.getMobileNo())).matches()) {
                response.put("status", "Invalid mobile number !!!");
            } else {
                // Set default role as "user" if role is null
                if (userDetailsInfo.getRole() == null) {
                    userDetailsInfo.setRole("USER");
                }

                // Parse date of birth string into LocalDate
//                String[] parts = userDetailsInfo.getDateOfbirth().split("-");
//                int day = Integer.parseInt(parts[0]);
//                int month = Integer.parseInt(parts[1]);
//                int year = Integer.parseInt(parts[2]);
//                userDetailsInfo.setDoB(LocalDate.of(year, month, day));

                // Encode password
                userDetailsInfo.setPassword(passwordEncoder.encode(userDetailsInfo.getPassword()));
                verification.generateAndSendOTP(userDetailsInfo.getEmailId());
                // Save UserDetailsInfo
                userDetailsRepo.save(userDetailsInfo);

                response.put("Status", "User created successfully");
            }
        } else {
            response.put("status", "Failed !!!");
            response.put("message", "User already exists");
        }

        return response;
    }

    @DeleteMapping("/deleteUser")
    public String deleteUser(@PathVariable String email) {
        return "deleted successfully" + email;
    }

    @GetMapping("/allUser")
    public List<UserDetailsInfo> getallUserDetails() {
        return  userDetailsRepo.findAll();
    }

    @GetMapping("/particular/user")
    public UserDetailsInfo getparticularUserDetails(@PathParam("email") String email) {
        return userDetailsRepo.findByEmailId(email);
    }

    @PostMapping("/authenticate")
    public JSONObject authenticateAndGetToken(@RequestBody AuthRequest authRequest) {
        org.springframework.security.core.Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        if (authentication.isAuthenticated()) {
            JSONObject response = jwtService.generateToken(authRequest.getUsername());
            return response;
        } else {
            System.out.println("invalid user");
        }
        return null;
    }

    @PostMapping("/forgot/password")
    public JSONObject UpdatePassword(@RequestBody UpdatePassword updatePassword){
        JSONObject response = new JSONObject();
        String TokenEmailId=userDetailsService.getUserEmail();
        if(updatePassword!=null) {
            if (TokenEmailId != null) {
                UserDetailsInfo userDetails = userDetailsRepo.findByEmailId(TokenEmailId);
                if (updatePassword.getPassword().equals(updatePassword.getConformPassword()) && updatePassword.getEmailId() != null) {
                    updatePassword.setPassword(passwordEncoder.encode(updatePassword.getPassword()));
                    userDetailsRepo.UpdateUserPassword(updatePassword.getEmailId(), updatePassword.getPassword());
                }
            } else {
                UserDetailsInfo userDetails = userDetailsRepo.findByEmailId(updatePassword.getEmailId());
                if (updatePassword.getPassword().equals(updatePassword.getConformPassword()) && updatePassword.getEmailId() != null) {
                    updatePassword.setPassword(passwordEncoder.encode(updatePassword.getPassword()));
                    userDetailsRepo.UpdateUserPassword(updatePassword.getEmailId(), updatePassword.getPassword());
                }
            }
            response.put("Status","successfully Updated!!!");
        }else {
            response.put("status","No data found to Update");
        }
        return response;
    }
    @PostMapping("/validate")
    public String validateOTP(@RequestParam String email, @RequestParam String otp) {
        return verification.validateOTP(email, otp);
    }
    @PostMapping("/create_otp")
    public String validateOTP(@RequestParam String email ) {
        return verification.generateAndSendOTP(email);
    }
}

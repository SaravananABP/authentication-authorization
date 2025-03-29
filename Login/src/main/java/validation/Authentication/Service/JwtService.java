package validation.Authentication.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * JwtService is a service class that provides JWT token generation and validation functionality.
 */
@Component
public class JwtService {

//    Logger logger = LoggerFactory.getLogger(JwtService.class);

    @Value("${token.timeout}")
    private Integer timeout;

    public static final String SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }



    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public boolean validateToken(String token, UserDetails userDetails) {
//        logger.debug("inside token validation");
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public JSONObject generateToken(String userName){
        Map<String,Object> claims=new HashMap<>();
        return createToken(claims,userName);
    }

    String tokenValue ;
    Boolean flag=false;
    private JSONObject createToken(Map<String, Object> claims, String userName) {
        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+timeout))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();

        tokenValue=token;


        JSONObject response = new JSONObject();
        response.put("status", "Success");
        response.put("token", token);
        response.put("issuedAt", new Date(System.currentTimeMillis()));
        response.put("expiresAt", new Date(System.currentTimeMillis()+timeout));
        response.put("timeoutInSeconds", timeout/1000);
        return response;
    }

    private Key getSignKey() {
        byte[] keyBytes= Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
    public String  getToken(){
        return tokenValue;
    }
}

package com.koala.rhschedule.service.securitymanager.impl;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.koala.rhschedule.model.RhUser;
import com.koala.rhschedule.service.securitymanager.TokenService;
import com.koala.rhschedule.service.securitymanager.UserTokenService;
import com.koala.rhschedule.util.CacheUtil;
import com.koala.rhschedule.util.ErrorCodeHelper;
import com.koala.rhschedule.util.UserToken;
import com.koala.rhschedule.util.constant.CommonConstants;
import com.koala.rhschedule.util.error.ErrorInfo;
import com.koala.rhschedule.util.exception.ServiceException;
import com.koala.rhschedule.util.property.reader.PropertyReader;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;

/**
 * Security Token Service Generating And Parsing Token
 *
 */

@Service
public class TokenServiceImpl implements TokenService {

	@Autowired
    @Qualifier(CommonConstants.SYSTEM_PROPERTY_READER)
    private PropertyReader systemPropertyReader;
	
    @Autowired
    @Qualifier(CommonConstants.ERROR_CODE_HELPER)
    private ErrorCodeHelper errorCodeHelper;

    @Autowired
    private UserTokenService userTokenService;
    
    @Autowired
    private CacheUtil cacheUtil;

    private final Logger logger = Logger.getLogger(TokenServiceImpl.class);

    private Key secret = MacProvider.generateKey();

    /**
     * Generate Security JWT token
     * 
     * @param userName
     * @param roles
     * @return UserToken object
     */
    @Override
	public UserToken generateUserToken(RhUser user, String roles) {

        Claims claims = Jwts.claims().setSubject(user.getUserMailid());
        claims.put(CommonConstants.ROLE, roles);
        claims.put(CommonConstants.CLAIM_TOKEN_VERSION, getRandomToken());
        
        UserToken token = new UserToken();
        token.setToken(Jwts.builder().setClaims(claims)
            .signWith(SignatureAlgorithm.HS512, secret).compact());
        token.setLastUsed(new Date().getTime());
        token.setSecret_key(secret.getEncoded());
        logger.debug(secret.toString());
        return token;
    }
    
    /**
     * Generates random key
     * 
     * @return
     */
    private Double getRandomToken() {

        Double randomToken = null;
        try {

            // Create a secure random number generator using the "SHA1PRNG" algorithm
            SecureRandom secureRandom = SecureRandom.getInstance(CommonConstants.RANDOM_NUMBER_GENERATOR_ALOG);
            randomToken = secureRandom.nextDouble();
        } catch (NoSuchAlgorithmException e) {
            logger.error("Invalid Algorithm used.", e);
        }

        return randomToken;

    }

    /**
    * Get user information from token
    * @param token
    * @return 
    */
    @Override
    public Map<String, Object> parseUserToken(String token) {
        logger.debug(secret.toString());
        Map<String, Object> userDetail = new HashMap<String, Object>();
        String userMailid = null;
        UserToken userToken = null;
        
        String tokenDetails = cacheUtil.getValueByKey(token);

		if (null != tokenDetails) {
			String[] tokenDetailIndex = tokenDetails.split(CommonConstants.SPECIAL_CHAR_SPLIT_TOKEN_DETAILS);
						
			userToken = new UserToken();
			userToken.setId(Long.parseLong(tokenDetailIndex[0]));
			userToken.setRhId(tokenDetailIndex[1]);
			userToken.setUserEmailId(tokenDetailIndex[2]);
			userToken.setLastUsed(Long.parseLong(tokenDetailIndex[3]));
			userToken.setSecret_key(tokenDetailIndex[4].getBytes());
			userToken.setSecret_key_str(tokenDetailIndex[4]);
			
			userToken.setToken(token);
			
		}
        if (userToken != null) {
            if (!isTokenExpired(userToken.getLastUsed())) {
                secret = new SecretKeySpec(userToken.getSecret_key(), SignatureAlgorithm.HS512.getJcaName());
                userMailid = userToken.getUserEmailId();
                userToken.setLastUsed(new Date().getTime());
                userToken.setSecret_key(secret.getEncoded());
            }else{
                
                logger.info( "TOKEN: " + userToken.getToken() + " EXPIRED FOR USER : " + userToken.getId() + ":" +userToken.getUserEmailId());
                ErrorInfo errorInfo = errorCodeHelper.getErrorInfo(CommonConstants.E1018_ERROR_CODE,
                    CommonConstants.E1018_ERROR_DESCRIPTION);
                throw new ServiceException(errorInfo, HttpStatus.UNAUTHORIZED);
            }
        }
        try {
            logger.info(token);
            Claims body = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
            if (body != null && !StringUtils.isEmpty(userMailid)) {
                if (userMailid.equals(body.getSubject())) {
                    userDetail.put("userMailid", body.getSubject());
                    userDetail.put(CommonConstants.ROLE, body.get(CommonConstants.ROLE, String.class));
                    userDetail.put(CommonConstants.USER_ID, userToken.getId());
                }

            }              
            cacheUtil.addKeyValuePair(userToken.getToken(),
            		userToken.getId() + CommonConstants.SPECIAL_CHAR_SPLIT_TOKEN_DETAILS + userToken.getRhId() +  CommonConstants.SPECIAL_CHAR_SPLIT_TOKEN_DETAILS + userMailid +  CommonConstants.SPECIAL_CHAR_SPLIT_TOKEN_DETAILS + userToken.getLastUsed() + CommonConstants.SPECIAL_CHAR_SPLIT_TOKEN_DETAILS + userToken.getSecret_key_str());
        }
        catch (ExpiredJwtException e) {
            logger.error(e);
            ErrorInfo errorInfo = errorCodeHelper.getErrorInfo(CommonConstants.E1018_ERROR_CODE,
                CommonConstants.E1018_ERROR_DESCRIPTION);
            throw new ServiceException(errorInfo, HttpStatus.UNAUTHORIZED);
        }
        catch (Exception e) {
            logger.error(e);
            ErrorInfo errorInfo = errorCodeHelper.getErrorInfo(CommonConstants.E1007_ERROR_CODE,
                CommonConstants.E1007_ERROR_DESCRIPTION);
            throw new ServiceException(errorInfo, HttpStatus.UNAUTHORIZED);

        }
       
        return userDetail;

    }

    /**
     * Checking whether token has expired
     * @param lastUsed
     * @return
     */
    @Override
    public boolean isTokenExpired(long lastUsed) {
        if (lastUsed +
            Integer.parseInt(systemPropertyReader.getProperty(CommonConstants.EXPIRATION_TIME)) *
                (CommonConstants.TOKEN_GET_LAST_TIME) < System.currentTimeMillis()) {
            return true;
        }
        return false;
    }
}

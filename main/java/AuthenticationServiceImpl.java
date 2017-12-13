package com.koala.rhschedule.service.securitymanager.impl;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Date;

import javax.transaction.Transactional;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.koala.rhschedule.model.RhUser;
import com.koala.rhschedule.service.securitymanager.AuthenticationService;
import com.koala.rhschedule.service.securitymanager.TokenService;
import com.koala.rhschedule.service.securitymanager.UserTokenService;
import com.koala.rhschedule.service.usermanager.UserService;
import com.koala.rhschedule.util.CacheUtil;
import com.koala.rhschedule.util.DateUtil;
import com.koala.rhschedule.util.ErrorCodeHelper;
import com.koala.rhschedule.util.UserToken;
import com.koala.rhschedule.util.constant.CommonConstants;
import com.koala.rhschedule.util.error.ErrorInfo;
import com.koala.rhschedule.util.exception.ServiceException;

/**
 * Authentication Service Authenticate User And Validate Token
 *
 */
@Service
@Transactional
public class AuthenticationServiceImpl implements AuthenticationService {

	private final Logger logger = Logger.getLogger(AuthenticationServiceImpl.class);

	@Autowired
	private TokenService tokenService;

	@Autowired
	private UserService userService;
	@Autowired
	private UserTokenService userTokenService;

	@Autowired
	@Qualifier(CommonConstants.ERROR_CODE_HELPER)
	private ErrorCodeHelper errorCodeHelper;
	
	@Autowired
	private CacheUtil cacheUtil;

	/**
	 * Authenticate User By userName And Password Generate token Store Token In
	 * Cache and Database
	 * 
	 * @param userName
	 * @param password
	 * @return UserToken Object
	 * @throws Exception
	 */
	@Override
	public UserToken authenticateUser(String userMailid) {

		String oldToken = null;
		String roles;
		Object[] userDetail = userService.findUserByEmail(userMailid);

		RhUser user;
		if (userDetail == null) {

			ErrorInfo errorInfo = errorCodeHelper.getErrorInfo(CommonConstants.E1000_ERROR_CODE,
					CommonConstants.E1000_ERROR_DESCRIPTION);
			throw new ServiceException(errorInfo);

		}
		user = (RhUser) userDetail[0];
		roles = (String) userDetail[1];
		UserToken userToken = null;
		boolean emailIdExists = cacheUtil.keyExists(userMailid);
		logger.debug("user token in db:" + userToken);

		if (emailIdExists) {
			userToken = new UserToken();
			oldToken = cacheUtil.getValueByKey(userMailid);
			userToken.setToken(oldToken);

			String tokenDetails = cacheUtil.getValueByKey(oldToken);

			if (null != tokenDetails) {
				String[] tokenDetailIndex = tokenDetails.split(CommonConstants.SPECIAL_CHAR_SPLIT_TOKEN_DETAILS);
				userToken.setId(Long.parseLong(tokenDetailIndex[0]));
				userToken.setRhId(tokenDetailIndex[1]);
				userToken.setUserEmailId(tokenDetailIndex[2]);
				userToken.setLastUsed(Long.parseLong(tokenDetailIndex[3]));
				userToken.setSecret_key(tokenDetailIndex[4].getBytes());
			}
		}

		if (userToken == null || tokenService.isTokenExpired(userToken.getLastUsed())) {			
			userToken = tokenService.generateUserToken(user, roles);
			cacheUtil.addKeyValuePair(userMailid, userToken.getToken());
			
			if(null!=oldToken){
				cacheUtil.replaceKey(oldToken, userToken.getToken());
			}
			
			userToken.setSecret_key_str(new String(userToken.getSecret_key()));
			cacheUtil.addKeyValuePair(userToken.getToken(),
					user.getId() +  CommonConstants.SPECIAL_CHAR_SPLIT_TOKEN_DETAILS + user.getRhId() +  CommonConstants.SPECIAL_CHAR_SPLIT_TOKEN_DETAILS + userMailid + CommonConstants.SPECIAL_CHAR_SPLIT_TOKEN_DETAILS + userToken.getLastUsed() + CommonConstants.SPECIAL_CHAR_SPLIT_TOKEN_DETAILS + userToken.getSecret_key_str());
		}

		return userToken;
	}

}

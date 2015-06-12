/*
 * $Id: NtlmFilter.java,v 1.3 2012/02/06 13:44:46 msc Exp $
 *
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */

package org.ntlmv2.filter;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import jcifs.util.Base64;
import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheException;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Element;
import net.sf.ehcache.ObjectExistsException;

import org.ntlmv2.liferay.NtlmManager;
import org.ntlmv2.liferay.NtlmUserAccount;
import org.ntlmv2.liferay.util.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Simplified NTLMv2 authentication filter, based on the original
 * <code>com.liferay.portal.servlet.filters.sso.ntlm.NtlmFilter</code>. The 
 * main purpose of this filter is to provide an example for the bare 
 * minimum required to create a working NTLMv2 authentication 
 * SSO filter, based on JCIFS, with some extensions from the Liferay product.
 * <p>
 * For references, please read the Liferay product documentation:
 * <p>
 * <a href="http://www.liferay.com">www.liferay.com</a>
 * <p>
 * The main reason for not using the unchanged code from within the Liferay 
 * jar libraries is that they contain dependencies to utility and configuration 
 * code of the Liferay server, which makes using them outside of Liferay pretty 
 * much impossible. However, I tried to make as few changes as possible.
 * <p>
 * Credit where credit is due, so I also left all the author tags of the 
 * original authors in the classes copied from Liferay.
 * 
 * @author Marcel Schoen
 * @author Bruno Farache
 * @author Marcus Schmidke
 * @author Brian Wing Shun Chan
 * @author Wesley Gong
 * @author Marcellus Tavares
 * @author Michael C. Han
 */
public class NtlmFilter implements Filter {

	/** Constant for session attribute name. */
	private static final String NTLM_USER_ACCOUNT = "ntlmUserAccount";

	/** debug logger reference. */
	private static Logger log = LoggerFactory.getLogger(NtlmFilter.class);

	/** Random number generator for challenge creation. */
	private SecureRandom secureRandom = new SecureRandom();

	/** 
	 * Stores reference to the singleton cache manager. Configure
	 * the cache by setting
	 */
	private static CacheManager singletonManager = null;

	/** Name of cache. */
	public static final String CACHE_NAME = "ntlmChallengeCache";

	/**
	 * NtlmManager instance. NOTE: In this filter, there's only one. In 
	 * the original Liferay NTLM filter, there were multiple instances 
	 * (one per company / tenant, I suppose). So, how to handle instances of
	 * this class may depend on your use-case.
	 */
	private NtlmManager ntlmManager = null;

	/*
	 * (non-Javadoc)
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 */
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		log.info("Initializing NTLMv2 filter...");
		try {
			singletonManager = CacheManager.create(this.getClass().getResourceAsStream("/ehcache.xml"));
			if(log.isTraceEnabled()) {
				log.trace("Add memory-only cache.");
			}
			String[] cacheNames = singletonManager.getCacheNames();
			if(cacheNames != null && cacheNames.length > 0) {
				for(String name : cacheNames) {
					if(log.isTraceEnabled()) {
						log.trace("Cache: " + name);
					}
				}
			} else {
				log.error("FAILED TO CREATE ANY CACHES !!");
			}
			if(log.isTraceEnabled()) {
				log.trace("NTLM challenge cache initialized.");
			}

		} catch(CacheException e) {
			String msg = "Failed to initialize cache: " + e.toString();
			throw new ServletException(msg, e);
		}
		try {
			// The Windows domain name
			String domain = filterConfig.getInitParameter("ntlm-domain");
			
			// The domain controller IP address
			String domainController = filterConfig.getInitParameter("ntlm-dc");
			
			// The domain controller hostname
			String domainControllerHostName = filterConfig.getInitParameter("ntlm-dc-name");
			
			// The computer account for the connection to the DC
			String serviceAccount = filterConfig.getInitParameter("ntlm-account");
			
			// The password of the computer account
			String servicePassword = filterConfig.getInitParameter("ntlm-password");

			log.info("Windows domain: " + domain);
			log.info("Domain controller IP address: " + domainController);
			log.info("Domain controller hostname: " + domainControllerHostName);
			log.info("Computer account name: " + serviceAccount);
			log.info("Computer account password: " + servicePassword);
			
			ntlmManager = new NtlmManager(
					domain, domainController, domainControllerHostName, serviceAccount,
					servicePassword);
			
		} catch (Exception e) {
			throw new ServletException("NTLM filter initialization failed. Reason: " + e, e);
		}
		log.info("NTLMv2 filter initialized.");
	}

	/* (non-Javadoc)
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)
	 */
	@Override
	public void doFilter(ServletRequest req, ServletResponse res,
			FilterChain filterChain) throws IOException, ServletException {

		log.debug("Process request...");
		HttpServletRequest request = (HttpServletRequest)req;
		HttpServletResponse response = (HttpServletResponse)res;
		
		// Type 1 NTLM requests from browser can (and should) always immediately
		// be replied to with an Type 2 NTLM response, no matter whether we're
		// yet logging in or whether it is much later in the session.

		HttpSession session = request.getSession(false);

		String authorization = request.getHeader("Authorization");

		if (authorization != null && authorization.startsWith("NTLM")) {

			Cache cache = singletonManager.getCache(CACHE_NAME);
			byte[] src = Base64.decode(authorization.substring(5));

			if (src[8] == 1) {
				log.debug("Create server challenge...");
				byte[] serverChallenge = new byte[8];

				secureRandom.nextBytes(serverChallenge);

				byte[] challengeMessage = ntlmManager.negotiate(
					src, serverChallenge);

				authorization = Base64.encode(challengeMessage);

				response.setContentLength(0);
				response.setHeader(
					HttpHeaders.WWW_AUTHENTICATE, "NTLM " + authorization);
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				response.flushBuffer();

				synchronized(cache) {
					if(log.isTraceEnabled()) {
						log.trace("Cache server challenge for: " + request.getRemoteAddr());
					}
					Element element = new Element(request.getRemoteAddr(), serverChallenge);
					cache.put(element);
				}

				// Interrupt filter chain, send response. Browser will
				// immediately post a new request.

				return;
			}

			byte[] serverChallenge = null;
			synchronized(cache) {
				Element challengeHolder;
				try {
					if(log.isTraceEnabled()) {
						log.trace("Get cached server challenge for: " + request.getRemoteAddr());
					}
					challengeHolder = cache.get(request.getRemoteAddr());
					serverChallenge = (byte[])challengeHolder.getValue();
				} catch (CacheException e) {
					// Something went wrong - just log it and start again
					if(log.isWarnEnabled()) {
						log.warn("No challenge found in cache for client: " + request.getRemoteAddr());
					}
				}
			}

			if (serverChallenge == null) {
				log.debug("Start NTLM login...");
				sendWwwAuthenticateResponse(response);

				return;
			}

			NtlmUserAccount ntlmUserAccount = null;
			try {
				log.debug("Try authenticating user now...");
				ntlmUserAccount = ntlmManager.authenticate(
					src, serverChallenge);
				log.info("Authentication was successful. Creating session.");
				session = request.getSession(true);
				session.setAttribute(NTLM_USER_ACCOUNT, ntlmUserAccount);
			} catch (Exception e) {
				log.error("NTLM authentication failed: " + e, e);
			} finally {
				synchronized(cache) {
					cache.remove(request.getRemoteAddr());
				}
			}

			if (ntlmUserAccount == null) {
				// No NTLM user in session yet, or authentication failed
				sendWwwAuthenticateResponse(response);
				return;
			}

			if (log.isDebugEnabled()) {
				log.debug("NTLM remote user " + ntlmUserAccount.getUserName());
			}
		}

		// Check if NTLM user account has already been stored in session
		NtlmUserAccount ntlmUserAccount = null;
		if (session != null) {
			ntlmUserAccount = (NtlmUserAccount)session.getAttribute(
					NTLM_USER_ACCOUNT);
		}

		HttpServletRequest filteredReq = request;
		if (ntlmUserAccount == null) {
			log.debug("No NTLM user set yet, begin authentication...");
			sendWwwAuthenticateResponse(response);
			return;
		}
		
		log.debug("NTLM user in session: " + ntlmUserAccount.getUserName());
		if(!(request instanceof NtlmV2HttpRequestWrapper)) {
			// Wrap original request only once
			filteredReq = new NtlmV2HttpRequestWrapper(request, ntlmUserAccount.getUserName());
		}
		
		filterChain.doFilter(filteredReq, res);
	}

	/**
	 * @param response
	 * @throws IOException
	 */
	private void sendWwwAuthenticateResponse(HttpServletResponse response)
			throws IOException {
		response.setContentLength(0);
		response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "NTLM");
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.flushBuffer();
	}

	/* (non-Javadoc)
	 * @see javax.servlet.Filter#destroy()
	 */
	@Override
	public void destroy() {
		removeEhCache();
	}

	/**
	 * Removes all EH caches.
	 */
	private static void removeEhCache() {
		try {
			log.debug("Remove memory-only cache.");
			CacheManager singletonManager = CacheManager.create();
			singletonManager.removeCache(CACHE_NAME);
			singletonManager.shutdown();
		} catch(Exception e) {
			// ignore
		}
	}
}
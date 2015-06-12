/*
 * $Id: NtlmV2HttpRequestWrapper.java,v 1.1 2012/02/02 20:07:06 msc Exp $
 *
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */

package org.ntlmv2.filter;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * Provides NTLM-authenticated user credentials.
 * 
 * @author Marcel Schoen
 */
public class NtlmV2HttpRequestWrapper extends HttpServletRequestWrapper {

	/** Stores the NTLM principal holder. */
	private Principal userPrincipal = null;
	
	/**
	 * Creates a request wrapper instance.
	 * 
	 * @param request The wrapped HTTP request.
	 */
	public NtlmV2HttpRequestWrapper(HttpServletRequest request, String userName) {
		super(request);
		userPrincipal = new NtlmV2Principal(userName);
	}

	/*
	 * (non-Javadoc)
	 * @see javax.servlet.http.HttpServletRequestWrapper#getRemoteUser()
	 */
	@Override
	public String getRemoteUser() {
		if(this.userPrincipal == null) {
			return super.getRemoteUser();
		}
		return userPrincipal.getName();
	}

	/*
	 * (non-Javadoc)
	 * @see javax.servlet.http.HttpServletRequestWrapper#getUserPrincipal()
	 */
	@Override
	public Principal getUserPrincipal() {
		if(this.userPrincipal == null) {
			return super.getUserPrincipal();
		}
		return this.userPrincipal;
	}
	
}

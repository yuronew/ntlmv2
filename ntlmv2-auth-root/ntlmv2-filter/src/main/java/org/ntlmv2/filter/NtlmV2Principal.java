/*
 * $Id: NtlmV2Principal.java,v 1.1 2012/02/02 20:07:06 msc Exp $
 *
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */

package org.ntlmv2.filter;

import java.security.Principal;

/**
 * Stores a principal authenticated through NTLM.
 * 
 * @author Marcel Schoen
 */
public class NtlmV2Principal implements Principal {

	/** Stores the NTLM username. */
	private String userName = null;
	
	/**
	 * Creates an NTLM principal holder.
	 * 
	 * @param userName The Windows username.
	 */
	public NtlmV2Principal(String userName) {
		this.userName = userName;
	}
	
	/* (non-Javadoc)
	 * @see java.security.Principal#getName()
	 */
	@Override
	public String getName() {
		return this.userName;
	}
}

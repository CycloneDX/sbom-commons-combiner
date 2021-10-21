/*
 * Copyright (c) 2018,2019 Lockheed Martin Corporation.
 *
 * This work is owned by Lockheed Martin Corporation. Lockheed Martin personnel are permitted to use and
 * modify this software.  Lockheed Martin personnel may also deliver this source code to any US Government
 * customer Agency under a "US Government Purpose Rights" license.
 *
 * See the LICENSE file distributed with this work for licensing and distribution terms
 */
package com.lmco.efoss.sbom.combiner.exceptions;

/**
 * (U) This class is the Software Bill of Materials (SBom) Combiner Exception class.
 * 
 * @author wrgoff
 * @since 17 August 2020
 */
public class SBomCombinerException extends Exception
{
	private static final long serialVersionUID = 5753980112031157353L;
	
	/**
	 * (U) Constructs a new SBomCombinerException with null as its details.
	 */
	public SBomCombinerException()
	{}
	
	/**
	 * (U) Constructs a new SBomCombinerException with the specified detail message.
	 *
	 * @param message String value to set the message to.
	 */
	public SBomCombinerException(String message)
	{
		super(message);
	}
	
	/**
	 * (U) Constructs a new SBomCombinerException with the specified detail message and cause.
	 *
	 * @param message String value to set the message to.
	 * @param cause   Throwable class to set the cause to.
	 */
	public SBomCombinerException(String message, Throwable cause)
	{
		super(message, cause);
	}
	
	/**
	 * (U) Constructs a new SBomCombinerException wit the specified detail message, cause,
	 * suppression flag set to either enabled or disabled, and the writable stack trace flag set to
	 * either enable or disabled.
	 *
	 * @param message             String value to set the message to.
	 * @param cause               Throwable class to set the cause to.
	 * @param enableSuppression   boolean used to set the enabled suppression flag to.
	 * @param writeableStackTrace boolean used to set the write able stack trace flag to.
	 */
	public SBomCombinerException(String message, Throwable cause, boolean enableSuppression,
			boolean writeableStackTrace)
	{
		super(message, cause, enableSuppression, writeableStackTrace);
	}
	
	/**
	 * (U) Constructs a new SBomCombinerException with the cause set.
	 * 
	 * @param cause Throwable class to set the cause to.
	 */
	public SBomCombinerException(Throwable cause)
	{
		super(cause);
	}
}

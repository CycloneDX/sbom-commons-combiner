/*
 * Copyright (c) 2018,2019 Lockheed Martin Corporation.
 *
 * This work is owned by Lockheed Martin Corporation. Lockheed Martin personnel are permitted to use and
 * modify this software.  Lockheed Martin personnel may also deliver this source code to any US Government
 * customer Agency under a "US Government Purpose Rights" license.
 *
 * See the LICENSE file distributed with this work for licensing and distribution terms
 */
package com.lmco.efoss.sbom.combiner.utils;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.cyclonedx.model.Bom;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.springframework.core.io.InputStreamSource;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;

import com.lmco.efoss.sbom.combiner.exceptions.SBomCombinerException;
import com.lmco.efoss.sbom.commons.test.utils.Log4JTestWatcher;
import com.lmco.efoss.sbom.commons.test.utils.TestUtils;
import com.lmco.efoss.sbom.commons.utils.DateUtils;

/**
 * (U) JUnit test for the SBomCombiner class.
 * 
 * @author wrgoff
 * @since 19 August 2020
 */
public class SBomCombinerTest
{
	private static final String LOG4J_FILE = "SbomCombinerAppender.xml";
	
	@ClassRule
	public static Log4JTestWatcher watcher = new Log4JTestWatcher(LOG4J_FILE,
			"SBomCombinerTest");
	
	private String sbomsDir = "./src/test/resources/sboms/";
	private String commonsSbom = "sbomcommons.json";
	private String comparatorSbom = "sbomcomparator.xml";
	
	/**
	 * (U) This Unit test, to test the combining of files from a list of file names (Strings).
	 */
	@Test
	public void combineListOfFileNamesString()
	{
		String methodName = new Object()
		{}.getClass().getEnclosingMethod().getName();
		
		Date startDate = DateUtils.rightNowDate();
		
		TestUtils.logTestStart(methodName, watcher.getLogger());
		
		Long expectedComponents = Long.valueOf(53);
		
		try
		{
			watcher.getLogger().debug("Attempting to read Bom from JSon file (" + sbomsDir +
					commonsSbom + ").");
			
			List<String> fileNames = new ArrayList<String>();
			fileNames.add(sbomsDir + commonsSbom);
			fileNames.add(sbomsDir + comparatorSbom);
			
			Bom combinedBom = SBomCombiner.combineSBomsFromStrings(fileNames);
			
			if (combinedBom != null)
			{
				if ((combinedBom.getComponents() != null) &&
						(combinedBom.getComponents().size() == expectedComponents))
				{
					watcher.getLogger().info("Successfully read in the expected " +
							combinedBom.getComponents().size() + " components.");
				}
				else
				{
					StringBuilder sb = new StringBuilder("Did NOT get the expected results:\n");
					sb.append("	Components: expected " + expectedComponents + ", got ");
					if (combinedBom.getComponents() != null)
						sb.append(combinedBom.getComponents().size() + "\n");
					else
						sb.append("null\n");
					watcher.getLogger().warn(sb.toString());
				}
			}
			Assert.assertEquals("Components", expectedComponents.longValue(),
					combinedBom.getComponents().size());
		}
		catch (Exception e)
		{
			String error = "Unexpected error occured while attempting to combine SBoms via List " +
					"of file names (Strings)!";
			watcher.getLogger().error(error, e);
			Assert.fail(error);
		}
		finally
		{
			TestUtils.logTestFinish(methodName, startDate, watcher.getLogger());
		}
	}
	
	/**
	 * (U) This Unit test, to test the File Not Found from a list of file names (Strings).
	 */
	@Test
	public void combineListOfFileNamesStringFileNotFoundTest()
	{
		String methodName = new Object()
		{}.getClass().getEnclosingMethod().getName();
		
		Date startDate = DateUtils.rightNowDate();
		
		TestUtils.logTestStart(methodName, watcher.getLogger());
		
		try
		{
			List<String> fileNames = new ArrayList<String>();
			fileNames.add(sbomsDir + commonsSbom);
			fileNames.add(sbomsDir + "somebogusFile.xml");
			
			Exception exception = Assert.assertThrows(SBomCombinerException.class, () ->
			{
				SBomCombiner.combineSBomsFromStrings(fileNames);
			});
			
			String expectedMessage = "somebogusFile.xml) does NOT exist!";
			String actualMessage = exception.getMessage();
			
			if (!actualMessage.contains(expectedMessage))
				watcher.getLogger().error("Actual error message does NOT contain expected " +
						"message!\n	Expected: " + expectedMessage + "\n	" + actualMessage);
			else
				watcher.getLogger().debug("Got expected Error message: " + actualMessage);
			
			Assert.assertTrue(actualMessage.contains(expectedMessage));
		}
		catch (Exception e)
		{
			String error = "Unexpected error occured while testing file NOT found!";
			watcher.getLogger().error(error, e);
			Assert.fail(error);
		}
		finally
		{
			TestUtils.logTestFinish(methodName, startDate, watcher.getLogger());
		}
	}
	
	/**
	 * (U) This Unit test, to test the combining of files from a list of file names
	 * (InputStreamSource).
	 */
	@Test
	public void combineListOfFileNamesInputStreamSource()
	{
		String methodName = new Object()
		{}.getClass().getEnclosingMethod().getName();
		
		Date startDate = DateUtils.rightNowDate();
		
		TestUtils.logTestStart(methodName, watcher.getLogger());
		
		Long expectedComponents = Long.valueOf(53);
		
		try (InputStream commonsInputStream = Thread.currentThread().getContextClassLoader()
				.getResourceAsStream("sboms/" + commonsSbom);
				InputStream comparatorInputStream = Thread.currentThread().getContextClassLoader()
						.getResourceAsStream("sboms/" + comparatorSbom))
		{
			watcher.getLogger().debug("Attempting to read Bom from JSon file (" + sbomsDir +
					commonsSbom + ").");
			
			List<InputStreamSource> files = new ArrayList<InputStreamSource>();
			MultipartFile commonsMFile = new MockMultipartFile("commonsBom.xml",
					commonsInputStream);
			files.add(commonsMFile);
			MultipartFile comparatorMFile = new MockMultipartFile("compatatorBom.xml",
					comparatorInputStream);
			files.add(comparatorMFile);
			
			Bom combinedBom = SBomCombiner.combineSBomsFromInputStreamSource(files);
			
			if (combinedBom != null)
			{
				if ((combinedBom.getComponents() != null) &&
						(combinedBom.getComponents().size() == expectedComponents))
				{
					watcher.getLogger().info("Successfully read in the expected " +
							combinedBom.getComponents().size() + " components.");
				}
				else
				{
					StringBuilder sb = new StringBuilder("Did NOT get the expected results:\n");
					sb.append("	Components: expected " + expectedComponents + ", got ");
					if (combinedBom.getComponents() != null)
						sb.append(combinedBom.getComponents().size() + "\n");
					else
						sb.append("null\n");
					watcher.getLogger().warn(sb.toString());
				}
			}
			
			Assert.assertEquals("Components", expectedComponents.longValue(),
					combinedBom.getComponents().size());
		}
		catch (Exception e)
		{
			String error = "Unexpected error occured while attempting to combine SBoms via List " +
					"of file names (InputStreamSource)!";
			watcher.getLogger().error(error, e);
			Assert.fail(error);
		}
		finally
		{
			TestUtils.logTestFinish(methodName, startDate, watcher.getLogger());
		}
	}
	
	/**
	 * (U) This Unit test, to test the File Not Found from a list of file names (InputStreamSource).
	 */
	@Test
	public void combineListOfFileNamesInputStreamSourceFileNotFoundTest()
	{
		String methodName = new Object()
		{}.getClass().getEnclosingMethod().getName();
		
		Date startDate = DateUtils.rightNowDate();
		
		TestUtils.logTestStart(methodName, watcher.getLogger());
		
		try (InputStream commonsInputStream = Thread.currentThread().getContextClassLoader()
				.getResourceAsStream("sboms/" + commonsSbom);
				InputStream comparatorInputStream = Thread.currentThread().getContextClassLoader()
						.getResourceAsStream("sboms/" + comparatorSbom);
				InputStream bogusInputStream = Thread.currentThread().getContextClassLoader()
						.getResourceAsStream("bogus"))
		{
			watcher.getLogger().debug("Attempting to read Bom from JSon file (" + sbomsDir +
					commonsSbom + ").");
			
			List<InputStreamSource> files = new ArrayList<InputStreamSource>();
			MultipartFile commonsMFile = new MockMultipartFile("commonsBom.xml",
					commonsInputStream);
			files.add(commonsMFile);
			MultipartFile comparatorMFile = new MockMultipartFile("compatatorBom.xml",
					comparatorInputStream);
			files.add(comparatorMFile);
			MultipartFile badMFile = new MockMultipartFile("bogusBom.xml",
					bogusInputStream);
			files.add(badMFile);
			
			Exception exception = Assert.assertThrows(SBomCombinerException.class, () ->
			{
				SBomCombiner.combineSBomsFromInputStreamSource(files);
			});
			
			String expectedMessage = "Failed to read bom file!";
			String actualMessage = exception.getMessage();
			
			if (!actualMessage.contains(expectedMessage))
				watcher.getLogger().error("Actual error message does NOT contain expected " +
						"message!\n	Expected: " + expectedMessage + "\n	" + actualMessage);
			else
				watcher.getLogger().debug("Got expected Error message: " + actualMessage);
			
			Assert.assertTrue(actualMessage.contains(expectedMessage));
		}
		catch (Exception e)
		{
			String error = "Unexpected error occured while testing file NOT found!";
			watcher.getLogger().error(error, e);
			Assert.fail(error);
		}
		finally
		{
			TestUtils.logTestFinish(methodName, startDate, watcher.getLogger());
		}
	}
	
	/**
	 * (U) This Unit test tests the reading of a Software Bill of Materials from a JSon file.
	 */
	@Test
	public void getJSonBomFileTest()
	{
		String methodName = new Object()
		{}.getClass().getEnclosingMethod().getName();
		
		Date startDate = DateUtils.rightNowDate();
		
		TestUtils.logTestStart(methodName, watcher.getLogger());
		
		Long expectedComponents = Long.valueOf(20);
		Long expectedDependencies = Long.valueOf(31);
		
		try
		{
			watcher.getLogger().debug("Attempting to read Bom from JSon file (" + sbomsDir +
					commonsSbom + ").");
			
			Bom commonsBom = SBomCombiner.getBomFile(sbomsDir + commonsSbom);
			
			if (commonsBom != null)
			{
				if ((commonsBom.getComponents() != null) &&
						(commonsBom.getComponents().size() == expectedComponents) &&
						(commonsBom.getDependencies() != null) &&
						(commonsBom.getDependencies().size() == expectedDependencies))
				{
					watcher.getLogger().info("Successfully read in the expected " +
							commonsBom.getComponents().size() + " components, and " +
							commonsBom.getDependencies().size() + " dependencies");
				}
				else
				{
					StringBuilder sb = new StringBuilder("Did NOT get the expected results:\n");
					sb.append("	Components: expected " + expectedComponents + ", got ");
					if (commonsBom.getComponents() != null)
						sb.append(commonsBom.getComponents().size() + "\n");
					else
						sb.append("null\n");
					sb.append("	Dependencies: expected " + expectedDependencies + ", got ");
					
					if (commonsBom.getDependencies() != null)
						sb.append(commonsBom.getDependencies().size());
					else
						sb.append("null\n");
					watcher.getLogger().warn(sb.toString());
				}
			}
			
			Assert.assertEquals("Components", expectedComponents.longValue(),
					commonsBom.getComponents().size());
			Assert.assertEquals("Dependencies", expectedDependencies.longValue(),
					commonsBom.getDependencies().size());
			
		}
		catch (Exception e)
		{
			String error = "Unexpected error occured while running read Sbom from a JSon file!";
			watcher.getLogger().error(error, e);
			Assert.fail(error);
		}
		finally
		{
			TestUtils.logTestFinish(methodName, startDate, watcher.getLogger());
		}
	}
	
	/**
	 * (U) This Unit test tests the reading of a Software Bill of Materials from a JSon file.
	 */
	@Test
	public void getXmlBomFileTest()
	{
		String methodName = new Object()
		{}.getClass().getEnclosingMethod().getName();
		
		Date startDate = DateUtils.rightNowDate();
		
		TestUtils.logTestStart(methodName, watcher.getLogger());
		
		Long expectedComponents = Long.valueOf(52);
		Long expectedDependencies = Long.valueOf(52);
		
		try
		{
			watcher.getLogger().debug("Attempting to read Bom from XML file (" + sbomsDir +
					comparatorSbom + ").");
			
			Bom bom = SBomCombiner.getBomFile(sbomsDir + comparatorSbom);
			
			if (bom != null)
			{
				if ((bom.getComponents() != null) &&
						(bom.getComponents().size() == expectedComponents) &&
						(bom.getDependencies() != null) &&
						(bom.getDependencies().size() == expectedDependencies))
				{
					watcher.getLogger().info("Successfully read in the expected " +
							bom.getComponents().size() + " components, and " +
							bom.getDependencies().size() + " dependencies");
				}
				else
				{
					StringBuilder sb = new StringBuilder("Did NOT get the expected results:\n");
					sb.append("	Components: expected " + expectedComponents + ", got ");
					if (bom.getComponents() != null)
						sb.append(bom.getComponents().size() + "\n");
					else
						sb.append("null\n");
					sb.append("	Dependencies: expected " + expectedDependencies + ", got ");
					
					if (bom.getDependencies() != null)
						sb.append(bom.getDependencies().size());
					else
						sb.append("null\n");
					watcher.getLogger().warn(sb.toString());
				}
			}
			
			Assert.assertEquals("Components", expectedComponents.longValue(),
					bom.getComponents().size());
			Assert.assertEquals("Dependencies", expectedDependencies.longValue(),
					bom.getDependencies().size());
			
		}
		catch (Exception e)
		{
			String error = "Unexpected error occured while running read Sbom from an XML file!";
			watcher.getLogger().error(error, e);
			Assert.fail(error);
		}
		finally
		{
			TestUtils.logTestFinish(methodName, startDate, watcher.getLogger());
		}
	}
}

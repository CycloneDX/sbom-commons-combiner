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

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Tool;
import org.springframework.core.io.InputStreamSource;

import com.lmco.efoss.sbom.combiner.exceptions.SBomCombinerException;
import com.lmco.efoss.sbom.commons.comparators.ComponentComparator;
import com.lmco.efoss.sbom.commons.utils.SBomCommonsException;
import com.lmco.efoss.sbom.commons.utils.SBomFileUtils;
import com.lmco.efoss.sbom.commons.utils.ToolsUtils;

/**
 * (U) This class is used to combine multiple Software Bill of Materials (SBom) into a single SBom.
 * 
 * @author wrgoff
 * @since 17 August 2020
 */
public class SBomCombiner
{
	private static final Logger logger = Logger.getLogger(SBomCombiner.class.getName());
	
	/**
	 * (U) Private Constructor as this class should not be instantiated.
	 */
	private SBomCombiner()
	{}
	
	/**
	 * (U) Because of a bug in CycloneDx's creation of a JSon SBom, I had to add this code to make
	 * Sure all External References have a type. Their code throws a Null Pointer.
	 * 
	 * @param component Component to check (and fill in if necessary) any External References
	 *                  without a type set.
	 */
	private static void checkReferenceTypes(Component component)
	{
		List<ExternalReference> refs = component.getExternalReferences();
		if (refs != null)
		{
			for (ExternalReference ref : refs)
			{
				if (ref.getType() == null)
					ref.setType(ExternalReference.Type.OTHER);
			}
		}
	}
	
	/**
	 * (U) This method is used to combine a list Software Bill of Materials (SWBom) into a single
	 * SWBom.
	 * 
	 * @param files List of Strings that are the file names to combine into a Single SBom.
	 * @return Bom Software Bill of Materials created from the list of files passed in.
	 * @throws SBomCombinerException in the event something goes wrong creating the SBom.
	 * @throws SBomCommonsException  if we are unable to load an SBom.
	 */
	public static Bom combineSBomsFromStrings(List<String> files)
			throws SBomCombinerException, SBomCommonsException
	{
		return combineCommonSBoms(files);
	}
	
	/**
	 * (U) This method is used to combine a list Software Bill of Materials (SWBom) into a single
	 * SWBom.
	 * 
	 * @param files List of InputStreamSource (org.springframework.core.io) that are the Stream
	 *              reference to the files to combine into a Single SBom.
	 * @return Bom Software Bill of Materials created from the list of files passed in.
	 * @throws SBomCombinerException in the event something goes wrong creating the SBom.
	 * @throws SBomCommonsException  if we are unable to load an SBom.
	 */
	public static Bom combineSBomsFromInputStreamSource(List<InputStreamSource> files)
			throws SBomCombinerException, SBomCommonsException
	{
		return combineCommonSBoms(files);
	}
	
	/**
	 * (U) This method is the actual method used to combine the Software Bill of Materials (SWBom)s
	 * into a single SWBom.
	 * 
	 * @param files List of objects to get the handle to the actual SWBoms to combine.
	 * @return Bom Software Bill of Materials created from the list of files passed in.
	 * @throws SBomCombinerException in the event something goes wrong creating the SBom.
	 * @throws SBomCommonsException  if we are unable to load an SBom.
	 */
	private static Bom combineCommonSBoms(List<?> files)
			throws SBomCombinerException, SBomCommonsException
	{
		Bom combinedSBom = new Bom();
		
		List<Component> components = new ArrayList<>();
		List<Dependency> dependencies = new ArrayList<>();
		
		List<Component> outerComps = new ArrayList<>();
		List<Tool> toolsUsed = new ArrayList<>();
		
		Bom bom = null;
		List<Component> bomComps;
		List<Dependency> bomDeps;
		List<Dependency> innerDeps;
		boolean dependencyFound = false;
		for (Object file : files)
		{
			if (file instanceof String)
				bom = getBomFile((String) file);
			else if (file instanceof InputStreamSource)
				bom = getBomFile((InputStreamSource) file);
			
			if (bom != null)
			{
				if ((bom.getMetadata() != null) && (bom.getMetadata().getTools() != null) &&
						(!bom.getMetadata().getTools().isEmpty()))
				{
					toolsUsed = ToolsUtils.addUniqueTools(toolsUsed, bom.getMetadata().getTools());
				}
			
				if ((bom.getMetadata() != null) && (bom.getMetadata().getComponent() != null))
					outerComps.add(bom.getMetadata().getComponent());
			
				bomComps = bom.getComponents();
				// Process Components.
				for (Component bomComp : bomComps)
				{
					if (!componentsContain(bomComp, components))
					{
						checkReferenceTypes(bomComp);
						components.add(bomComp);
					}
					else
						logger.debug("We already have component(" + bomComp.getName() + ", " +
								bomComp.getGroup() + ", " + bomComp.getVersion() + ")");
				}
				
				// Process Dependencies.
				bomDeps = bom.getDependencies();
				if ((bomDeps != null) && (!bomDeps.isEmpty()))
				{
					for (Dependency bomDep : bomDeps)
					{
						dependencyFound = false;
						for (Dependency dep : dependencies)
						{
							if (dep.equals(bomDep))
							{
								dependencyFound = true;
								logger.debug("Dependency (" + dep.getRef() +
										") found.  Adding inner depenencies.");
								innerDeps = bomDep.getDependencies();
								if (innerDeps != null)
								{
									for (Dependency innerDep : innerDeps)
									{
										dep.addDependency(innerDep);
									}
								}
							}
						}
						if (!dependencyFound)
							dependencies.add(bomDep);
					}
				}
			}
		}
		
		// Add in outer Components if they are not already there.
		for (Component bomComp : outerComps)
		{
			if (!componentsContain(bomComp, components))
			{
				checkReferenceTypes(bomComp);
				components.add(bomComp);
			}
			else
				logger.debug("We already have component(" + bomComp.getName() + ", " +
						bomComp.getGroup() + ", " + bomComp.getVersion() + ")");
		}
		if (combinedSBom.getMetadata() == null)
		{
			Metadata combinedSBomMetadata = new Metadata();
			combinedSBomMetadata.setTools(toolsUsed);
			combinedSBom.setMetadata(combinedSBomMetadata);
		}
		else
		{
			combinedSBom.getMetadata().setTools(toolsUsed);
		}
		combinedSBom.setComponents(components);
		combinedSBom.setDependencies(dependencies);
		return combinedSBom;
	}
	
	/**
	 * (U) This method is used to look for the component in the list of components. It uses the
	 * custom "ComponentComparator" to look for a component with the same name, group, and version.
	 * 
	 * @param comp       Component we are looking for.
	 * @param components List of components to look for the component in.
	 * @return boolean either true we found it. Or false we did not.
	 */
	private static boolean componentsContain(Component comp, List<Component> components)
	{
		ComponentComparator customComparator = new ComponentComparator();
		
		for (Component component : components)
		{
			if (customComparator.equals(comp, component))
				return true;
		}
		return false;
	}
	
	/**
	 * (U) This method is used to read a Software Bill of Materials (SBom) file it into a Bom
	 * Object.
	 * 
	 * @param fileName String value of the file name to read in.
	 * @return Bom CycloneDx Bom object the file has been read into.
	 * @throws SBomCombinerException in the event the file can not be read into a Bom object.
	 * @throws SBomCommonsException  in the event we fail to create an SBom from the file's data.
	 */
	public static Bom getBomFile(String fileName) throws SBomCombinerException, SBomCommonsException
	{
		Bom bom = null;
		
		if (logger.isDebugEnabled())
			logger.debug("Attempting to load SBom (" + fileName + ")");
		
		if ((fileName != null) && (fileName.trim().length() > 0))
		{
			File file = new File(fileName);
			if ((file.exists()) && (file.canRead()))
				bom = SBomFileUtils.processFile(file);
			else if (file.exists())
				throw new SBomCombinerException("Unable to read SBom from file(" +
						fileName + ").");
			else
				throw new SBomCombinerException("File(" + fileName + ") does NOT exist!");
		}
		
		return bom;
	}
	
	/**
	 * (U) This method is used to read the bom file from an InputStreamSource.
	 * 
	 * @param source InputStreamSource to read the Bom from.
	 * @return Bom read from the InputStreamSource passed in.
	 * @throws SBomCombinerException in the event the file can not be read into a Bom object.
	 */
	public static Bom getBomFile(InputStreamSource source)
			throws SBomCombinerException
	{
		Bom bom = null;
		
		try
		{
			bom = SBomFileUtils.processInputStream(source.getInputStream());
		}
		catch (Exception e)
		{
			String error = "Failed to read bom file!";
			logger.error(error, e);
			throw new SBomCombinerException(error);
		}
		return bom;
	}
}

# sbom-commons-combiner
Lockheed Martin developed common library to combine multiple SBOMs

## Overview/Description of Project
This project contains common classes used by the SBomCombiner Application and SBomCombinerService (web service).
The SbomCommonsCombiner project is not intended as a standalone application, this project was written with test driven development to validate the project's methods and classes.  Additions should have paired junit tests.  

## Prerequisites
- Open JDK11 (1.8 compliant)
- Apache Maven 3.6.3 or greater installed 
- (Recommended) java IDE Eclipse with Subclipse 4.3.0 plug-in

## Docs
### Usage
#### How to Install/Setup Project
##### Local Install
- Clone this git repository 
- Compile first time with the Maven Command `mvn clean install`. The project is not intended as a standalone application, but instead to hold commonalities between the SBOM projects, such as the Date utility. The project was written as a test driven development to validate the methods and classes in this project and additions should have paired JUnit tests. Tests can be verified through the Maven Command `mvn clean test`.

##### Add to your existing Maven Project
With maven configured to connect to [nexus.us.lmco.com](https://nexus.us.lmco.com/) you can add following dependency to your pom.xml (note you will have to edit `TAG-Version`)
```
		<dependency>
			<groupId>com.lmco.efoss.combiner</groupId>
			<artifactId>SBomCommonsCombiner</artifactId>
			<version>TAG-Version</version>
		</dependency>
```
After the dependency is added to your POM you can reference the classes found in this project by adding the import, `import com.lmco.efoss.sbom.combiner.*`, to your java class.

#### How to Run/Use This Project
The project is not intended as a standalone application, the JUnit tests can be verified through the Maven Command `mvn clean test`.

## License
[Licenses](./LICENSE) for this project.


/*
 * Copyright 2011 The Kuali Foundation
 *
 * Licensed under the Educational Community License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.opensource.org/licenses/ecl1.php
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.kuali.rice.kns.service;

import java.util.List;
import java.util.Map;

/**
 * 
 * @author Kuali Rice Team (rice.collab@kuali.org)
 */
public interface DataObjectMetaDataService {

    /**
     *
     * This method checks the DataDictionary and OJB Repository File to determine the primary
     * fields names for a given class.
     *
     * @param clazz The Class to check for primary keys
     * @return a list of the primary key field names or an empty list if none are found
     */
    public List<String> listPrimaryKeyFieldNames(Class<?> clazz);
   
    /**
     * @param DataObject object whose primary key field name,value pairs you want
     * @return a Map containing the names and values of fields for the given class which
     *         are designated as key fields in the OJB repository file or DataDictionary
     * @throws IllegalArgumentException if the given Object is null
     */
    public Map<String, ?> getPrimaryKeyFieldValues(Object dataObject);

    
    /**
     * @param persistableObject object whose primary key field name,value pairs you want
     * @param sortFieldNames if true, the returned Map will iterate through its entries sorted by fieldName
     * @return a Map containing the names and values of fields for the given class which
     *         are designated as key fields in the OJB repository file or DataDictionary
     * @throws IllegalArgumentException if the given Object is null
     */
    public Map<String, ?> getPrimaryKeyFieldValues(Object dataObject, boolean sortFieldNames);

    /**
     * Compares two dataObject instances for equality of type and key values using toString()
     * of each value for comparison purposes.
     * 
     * @param do1
     * @param do2
     * @return boolean indicating whether the two objects are equal.
     */
    boolean equalsByPrimaryKeys(Object do1, Object do2);
}

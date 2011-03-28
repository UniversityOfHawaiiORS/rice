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
package edu.sampleu.travel.service;

import java.util.Map;

import org.kuali.rice.core.resourceloader.GlobalResourceLoader;
import org.kuali.rice.kns.document.MaintenanceDocument;
import org.kuali.rice.kns.maintenance.KualiMaintainableImpl;
import org.kuali.rice.kns.util.KNSConstants;

import edu.sampleu.travel.dto.FiscalOfficerInfo;

/**
 * 
 * @author Kuali Rice Team (rice.collab@kuali.org)
 */
public class FiscalOfficerInfoMaintainableImpl extends KualiMaintainableImpl {
    
    private transient FiscalOfficerService fiscalOfficerService;

    
    @Override
    public void saveBusinessObject() {
        if(getMaintenanceAction().equals(KNSConstants.MAINTENANCE_NEW_ACTION) ||
                getMaintenanceAction().equals(KNSConstants.MAINTENANCE_COPY_ACTION)) {
            getFiscalOfficerService().createFiscalOfficer((FiscalOfficerInfo)getDataObject());
        }
        else {
            getFiscalOfficerService().updateFiscalOfficer((FiscalOfficerInfo)getDataObject());
        }
    }

    @Override
    public Object retrieveObjectForEditOrCopy(MaintenanceDocument document, Map<String, String> dataObjectKeys) {
        return getFiscalOfficerService().retrieveFiscalOfficer(new Long(dataObjectKeys.get("id")));
    }

    protected FiscalOfficerService getFiscalOfficerService() {
        if(fiscalOfficerService == null) {
            fiscalOfficerService = GlobalResourceLoader.getService("fiscalOfficerService");
        }
        return this.fiscalOfficerService;
    }

    public void setFiscalOfficerService(FiscalOfficerService fiscalOfficerService) {
        this.fiscalOfficerService = fiscalOfficerService;
    }

}

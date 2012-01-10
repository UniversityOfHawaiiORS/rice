/**
 * Copyright 2005-2012 The Kuali Foundation
 *
 * Licensed under the Educational Community License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.opensource.org/licenses/ecl2.php
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.kuali.rice.krms.api.repository.proposition;

import java.io.Serializable;
import java.util.Collection;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import org.apache.commons.lang.StringUtils;
import org.kuali.rice.core.api.CoreConstants;
import org.kuali.rice.core.api.mo.AbstractDataTransferObject;
import org.kuali.rice.core.api.mo.ModelBuilder;

/**
 * Concrete model object implementation of KRMS Proposition Parameter 
 * immutable. 
 * Instances of PropositionParameter can be (un)marshalled to and from XML.
 *
 * @see PropositionParameterContract
 */
@XmlRootElement(name = PropositionParameter.Constants.ROOT_ELEMENT_NAME)
@XmlAccessorType(XmlAccessType.NONE)
@XmlType(name = PropositionParameter.Constants.TYPE_NAME, propOrder = {
		PropositionParameter.Elements.ID,
		PropositionParameter.Elements.PROP_ID,
		PropositionParameter.Elements.VALUE,
		PropositionParameter.Elements.PARM_TYPE,
		PropositionParameter.Elements.SEQUENCE,
        CoreConstants.CommonElements.VERSION_NUMBER,
		CoreConstants.CommonElements.FUTURE_ELEMENTS
})
public final class PropositionParameter extends AbstractDataTransferObject implements PropositionParameterContract {
	private static final long serialVersionUID = 2783959459503209577L;

	@XmlElement(name = Elements.ID, required=true)
	private String id;
	@XmlElement(name = Elements.PROP_ID, required=true)
	private String propId;
	@XmlElement(name = Elements.VALUE, required=true)
	private String value;
	@XmlElement(name = Elements.PARM_TYPE, required=true)
	private String parameterType;
	@XmlElement(name = Elements.SEQUENCE, required=true)
	private Integer sequenceNumber;
    @XmlElement(name = CoreConstants.CommonElements.VERSION_NUMBER, required = false)
    private final Long versionNumber;
	
	@SuppressWarnings("unused")
    @XmlAnyElement
    private final Collection<org.w3c.dom.Element> _futureElements = null;
	
	 /** 
     * This constructor should never be called.  
     * It is only present for use during JAXB unmarshalling. 
     */
    private PropositionParameter() {
    	this.id = null;
    	this.propId = null;
    	this.value = null;
    	this.parameterType = null;
    	this.sequenceNumber = null;
        this.versionNumber = null;
    }
    
    /**
	 * Constructs a PropositionParameter from the given builder.  
	 * This constructor is private and should only ever be invoked from the builder.
	 * 
	 * @param builder the Builder from which to construct the PropositionParameter
	 */
    private PropositionParameter(Builder builder) {
        this.id = builder.getId();
        this.propId = builder.getPropId();
        this.value = builder.getValue();
        this.parameterType = builder.getParameterType();
        this.sequenceNumber = builder.getSequenceNumber();
        this.versionNumber = builder.getVersionNumber();
    }
    
	@Override
	public String getId() {
		return this.id;
	}
	
	@Override
	public String getPropId() {
		return this.propId;
	}

	@Override
	public String getValue() {
		return this.value;
	}

	@Override
	public String getParameterType() {
		return this.parameterType;
	}
	@Override
	public Integer getSequenceNumber() {
		return this.sequenceNumber; 
	}

    @Override
    public Long getVersionNumber() {
        return versionNumber;
    }
        
	/**
     * This builder is used to construct instances of PropositionParameter.  
     * It enforces the constraints of the {@link PropositionParameterContract}.
     */
    public static class Builder implements PropositionParameterContract, ModelBuilder, Serializable {
    	private static final long serialVersionUID = -6889320709850568900L;
		
		private String id;
        private String propId;
        private String value;
        private String parameterType;
        private Integer sequenceNumber;
        private Long versionNumber;
        private PropositionDefinition.Builder proposition;

		/**
		 * Private constructor for creating a builder with all of it's required attributes.
		 */
        private Builder(String id, String propId, String value, String parameterType, Integer sequenceNumber) {
            setId(id);
            setPropId(propId);
            setValue(value);
            setParameterType(parameterType);
			setSequenceNumber(sequenceNumber);
        }

        /**
         * Create a builder using the given values
         * @param id
         * @param propId
         * @param value
         * @param parameterType
         * @param sequenceNumber
         * @return Builder
         */
        public static Builder create(String id, String propId, String value, String parameterType, Integer sequenceNumber) {
        	return new Builder(id, propId, value, parameterType, sequenceNumber);
        }

        /**
         * Creates a builder by populating it with data from the given {@link PropositionParameterContract}.
         * 
         * @param contract the contract from which to populate this builder
         * @return an instance of the builder populated with data from the contract
         */
        public static Builder create(PropositionParameterContract contract) {
        	if (contract == null) {
                throw new IllegalArgumentException("contract is null");
            }
            Builder builder =  new Builder(contract.getId(), contract.getPropId(), contract.getValue(), contract.getParameterType(), contract.getSequenceNumber());
            builder.setVersionNumber(contract.getVersionNumber());
            return builder;
        }

		/**
		 * Sets the value of the id on this builder to the given value.
		 * 
		 * @param id the id value to set, must not be null or blank
		 * @throws IllegalArgumentException if the id is null or blank
		 */
        public void setId(String id) {
            if (id != null && StringUtils.isBlank(id)) {
                throw new IllegalArgumentException("id must not be null or blank");
            }
            this.id = id;
        }

        /**
         * Sets the value of the propId on this builder to the given value.
         *
         * @param propId the propId value to set, must not be null or blank
         * @throws IllegalArgumentException if the propId is null or blank
         */
		public void setPropId(String propId) {
		    // have to be able to create it with a null propId for chicken/egg reasons.
            if (null != propId && StringUtils.isBlank(propId)) {
                throw new IllegalArgumentException("propId must be not be null or blank");
            }
			this.propId = propId;
		}

        /**
         * Sets the value of the value on this builder to the given value.
         *
         * @param value the value value to set, must not be null or blank
         * @throws IllegalArgumentException if the value is null or blank
         */
		public void setValue(String value) {
            if (StringUtils.isBlank(value)) {
                throw new IllegalArgumentException("value must not be null or blank");
            }
			this.value = value;
		}

        /**
         * Sets the value of the parameterType on this builder to the given value.
         *
         * @param parameterType the value parameterType to set, must not be null or blank
         * @throws IllegalArgumentException if the parameterType is null, blank, or invalid
         */
		public void setParameterType(String parameterType) {
			if (StringUtils.isBlank(parameterType)){
	                throw new IllegalArgumentException("parameter type is null or blank");
			}
			if (!PropositionParameterType.VALID_TYPE_CODES.contains(parameterType)){
                throw new IllegalArgumentException("parameter type is invalid");				
			}
			// TODO: check against valid values
			this.parameterType = parameterType;
		}

        /**
         * Sets the value of the sequenceNumber on this builder to the given value.
         *
         * @param sequenceNumber the value sequenceNumber to set, must not be null or blank
         * @throws IllegalArgumentException if the sequenceNumber is null, blank, or invalid
         */
		public void setSequenceNumber(Integer sequenceNumber) {
			if (sequenceNumber == null) {
                throw new IllegalArgumentException("sequenceNumber type is blank");
			}
			this.sequenceNumber = sequenceNumber;
		}

        /**
         * Sets the value of the proposition on this builder to the given value.
         *
         * @param proposition the value proposition to set
         */
		public void setProposition(PropositionDefinition.Builder proposition) {
		    if (proposition != null && !StringUtils.isBlank(proposition.getId())) {
		        setPropId(proposition.getId());
		    }
		    this.proposition = proposition;
		}

        /**
         * Sets the value of the versionNumber on this builder to the given value.
         *
         * @param versionNumber the value versionNumber to set
         */
        public void setVersionNumber(Long versionNumber){
            this.versionNumber = versionNumber;
        }
        
		@Override
		public String getId() {
			return id;
		}

		@Override
		public String getPropId() {
			return propId;
		}

		@Override
		public String getValue() {
			return value;
		}

		@Override
		public String getParameterType() {
			return parameterType;
		}

		@Override
		public Integer getSequenceNumber() {
			return sequenceNumber;
		}

        @Override
        public Long getVersionNumber() {
            return versionNumber;
        }

		/**
		 * Builds an instance of a PropositionParameter based on the current state of the builder.
		 * 
		 * @return the fully-constructed PropositionParameter
		 */
        @Override
        public PropositionParameter build() {
            if (proposition == null && StringUtils.isBlank(propId)) {
                throw new IllegalStateException("either proposition must be non-null or propId must be non-blank");
            }
            return new PropositionParameter(this);
        }
		
    }
	
	/**
	 * Defines some internal constants used on this class.
	 */
	static class Constants {
		final static String ROOT_ELEMENT_NAME = "PropositionParameter";
		final static String TYPE_NAME = "PropositionParameterType";
	}
	
	/**
	 * A private class which exposes constants which define the XML element names to use
	 * when this object is marshalled to XML.
	 */
	public static class Elements {
		final static String ID = "id";
		final static String PROP_ID = "propId";
		final static String VALUE = "value";
		final static String PARM_TYPE = "parameterType";
		final static String SEQUENCE = "sequenceNumber";
	}

}

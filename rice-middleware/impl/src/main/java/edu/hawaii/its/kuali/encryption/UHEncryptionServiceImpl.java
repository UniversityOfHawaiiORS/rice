/*
 * Copyright 2006-2008 The Kuali Foundation Licensed under the Educational Community License,
 * Version 2.0 (the "License"); you may not use this file except in compliance with the License. You
 * may obtain a copy of the License at http://www.opensource.org/licenses/ecl2.php Unless required
 * by applicable law or agreed to in writing, software distributed under the License is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See
 * the License for the specific language governing permissions and limitations under the License.
 */
package edu.hawaii.its.kuali.encryption;

import java.security.GeneralSecurityException;

import org.apache.commons.lang.StringUtils;
import org.kuali.rice.core.api.encryption.EncryptionService;

/**
 * Implementation of the UH encryption service.
 * 
 * @author cahana
 */
public class UHEncryptionServiceImpl
implements EncryptionService
{

    private boolean isEnabled = false;

    private AesEncryptor encryptor;

    public String encrypt(Object valueToHide)
    throws GeneralSecurityException
    {
        if (valueToHide == null || StringUtils.isEmpty(valueToHide.toString())) {
            return "";
        }

        return encryptor.encrypt(valueToHide.toString());
    }

    public String decrypt(String ciphertext)
    throws GeneralSecurityException
    {
        if (StringUtils.isBlank(ciphertext)) {
            return "";
        }

        return encryptor.decrypt(ciphertext);
    }

    public byte[] encryptBytes(byte[] valueToHide)
    throws GeneralSecurityException
    {
        if (valueToHide == null) {
            return new byte[0];
        }

        return encryptor.encrypt(valueToHide);
    }

    public byte[] decryptBytes(byte[] ciphertext)
    throws GeneralSecurityException
    {
        if (ciphertext == null) {
            return new byte[0];
        }

        return encryptor.decrypt(ciphertext);
    }

    /**
     * Hash the value by converting to a string, running the hash algorithm, and
     * then base64'ng the results. Returns a blank string if any problems occur
     * or the input value is null or empty.
     * 
     * @see org.kuali.rice.kns.service.EncryptionService#hash(java.lang.Object)
     */
    public String hash(Object valueToHide)
    throws GeneralSecurityException
    {
        if (valueToHide == null || StringUtils.isEmpty(valueToHide.toString())) {
            return "";
        }
        return valueToHide.toString();
    }

    /**
     * @param encryptor
     *            the encryptor to set
     */
    public void setEncryptor(AesEncryptor encryptor)
    {
        this.encryptor = encryptor;
    }

    public boolean isEnabled()
    {
        return isEnabled;
    }

    public void setEnabled(boolean isEnabled)
    {
        this.isEnabled = isEnabled;
    }
}


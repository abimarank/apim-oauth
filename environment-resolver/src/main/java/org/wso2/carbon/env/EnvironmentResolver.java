/*
 *
 *  * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.wso2.carbon.env;

import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;

public class EnvironmentResolver extends AbstractMediator {

    public boolean mediate(MessageContext messageContext) {

        String host = System.getProperty("environment.host");
        String port = System.getProperty("environment.port");

        messageContext.setProperty("uri.var.host", host);
        messageContext.setProperty("uri.var.port", port);

        return true;
    }

    @Override
    public boolean isContentAware(){
        return false;
    }
}

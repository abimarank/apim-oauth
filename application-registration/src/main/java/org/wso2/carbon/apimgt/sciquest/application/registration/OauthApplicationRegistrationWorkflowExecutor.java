package org.wso2.carbon.apimgt.sciquest.application.registration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.WorkflowResponse;
import org.wso2.carbon.apimgt.impl.dao.ApiMgtDAO;
import org.wso2.carbon.apimgt.impl.dto.ApplicationRegistrationWorkflowDTO;
import org.wso2.carbon.apimgt.impl.dto.WorkflowDTO;
import org.wso2.carbon.apimgt.impl.workflow.AbstractApplicationRegistrationWorkflowExecutor;
import org.wso2.carbon.apimgt.impl.workflow.GeneralWorkflowResponse;
import org.wso2.carbon.apimgt.impl.workflow.WorkflowException;
import org.wso2.carbon.apimgt.impl.workflow.WorkflowStatus;

import java.util.List;

/**
 * This class provides the facility to map the external oauth application with api manager internal oauth application
 *
 */

public class OauthApplicationRegistrationWorkflowExecutor extends AbstractApplicationRegistrationWorkflowExecutor {
    private static final Log log = LogFactory.getLog(OauthApplicationRegistrationWorkflowExecutor.class);

    /**
     * Execute the workflow executor
     *
     * @param workFlowDTO - {@link org.wso2.carbon.apimgt.impl.dto.ApplicationRegistrationWorkflowDTO}
     * @throws org.wso2.carbon.apimgt.impl.workflow.WorkflowException
     */

    public WorkflowResponse execute(WorkflowDTO workFlowDTO) throws WorkflowException {

        if (log.isDebugEnabled()) {
            log.info("Executing Application creation Workflow..");
        }

        workFlowDTO.setStatus(WorkflowStatus.APPROVED);
        complete(workFlowDTO);
        super.publishEvents(workFlowDTO);
        return new GeneralWorkflowResponse();
    }

    /**
     * Complete the external process status
     * Based on the workflow status we will update the status column of the
     * Application table
     *
     * @param workFlowDTO - WorkflowDTO
     */
    public WorkflowResponse complete(WorkflowDTO workFlowDTO) throws WorkflowException {
        if (log.isDebugEnabled()) {
            log.info("Complete  Application Registration Workflow..");
        }

        ApplicationRegistrationWorkflowDTO regWFDTO = (ApplicationRegistrationWorkflowDTO) workFlowDTO;


        ApiMgtDAO dao = new ApiMgtDAO();

        try {
            dao.createApplicationRegistrationEntry((ApplicationRegistrationWorkflowDTO) workFlowDTO, false);
            //generateKeysForApplication(regWFDTO);
        } catch (APIManagementException e) {
            String msg = "Error occured when updating the status of the Application creation process";
            log.error(msg, e);
            throw new WorkflowException(msg, e);
        }
        return new GeneralWorkflowResponse();
    }

    @Override
    public List<WorkflowDTO> getWorkflowDetails(String workflowStatus) throws WorkflowException {
        return null;
    }
}

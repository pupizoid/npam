using System;
using System.Collections.Generic;
using Npam.Interop;

namespace Npam
{
    public static class NpamUser
    { 
        private const int AuthenticateFlags = 0;
        private const int AccountManagementFlags = 0;
        private const int ChangeAuthTokenFlags = 0;

        public static bool Authenticate(string serviceName, string user, string password) {
            //Initialize
            PamStatus lastReturnedValue = PamStatus.PAM_SUCCESS;
            IntPtr pamHandle = IntPtr.Zero;
            PamConv conversation = new PamConv();
            ConversationHandler conversationHandler = new ConversationHandler(password);
            conversation.ConversationCallback = conversationHandler.HandlePamConversation;

            try {
                //Start
                lastReturnedValue = Pam.pam_start(serviceName, user, conversation, ref pamHandle);
                if (lastReturnedValue != PamStatus.PAM_SUCCESS) return false;
                //Authenticate - Verifies username and password
                lastReturnedValue = Pam.pam_authenticate(pamHandle, AuthenticateFlags);
                if (lastReturnedValue != PamStatus.PAM_SUCCESS) return false;
                //Account Management - Checks that account is valid, checks account expiration, access restrictions.
                lastReturnedValue = Pam.pam_acct_mgmt(pamHandle, AccountManagementFlags);
                if (lastReturnedValue != PamStatus.PAM_SUCCESS) return false;
            } finally {
                lastReturnedValue = Pam.pam_end(pamHandle, lastReturnedValue);
            }

            return true;
        }

        public static IEnumerable<Group> GetGroups(string user) {
            AccountInfo info = StdLibC.GetPwNamAsAccountInfo(user);
            if (info == null) yield break;
            int numGroups = 0;
            int[] groupIdArray = new int[numGroups];
            StdLibC.getgrouplist(user, info.GroupID, groupIdArray, ref numGroups);
            groupIdArray = new int[numGroups];
            StdLibC.getgrouplist(user, info.GroupID, groupIdArray, ref numGroups);
            foreach (var groupId in groupIdArray)
                yield return StdLibC.GetGrGidAsGroup(groupId);
        }

        public static void ChangePassword(string serviceName, string user, string password)
        {
            PamStatus lastReturnedValue = PamStatus.PAM_SUCCESS;
            IntPtr pamHandle = IntPtr.Zero;
            PamConv conversation = new PamConv();
            ConversationHandlerForChangeToken conversationHandler = new ConversationHandlerForChangeToken(password);
            conversation.ConversationCallback = conversationHandler.HandlePamConversation;

            try
            {
                lastReturnedValue = Pam.pam_start(serviceName, user, conversation, ref pamHandle);
                if (lastReturnedValue != PamStatus.PAM_SUCCESS) throw new InvalidOperationException($"pam_start failed with {lastReturnedValue}");
                
                lastReturnedValue = Pam.pam_chauthtok(pamHandle, ChangeAuthTokenFlags);
                if (lastReturnedValue != PamStatus.PAM_SUCCESS) throw new InvalidOperationException($"pam_chauthtok failed with {lastReturnedValue}");
                //Account Management - Checks that account is valid, checks account expiration, access restrictions.
                lastReturnedValue = Pam.pam_acct_mgmt(pamHandle, AccountManagementFlags);
                if (lastReturnedValue != PamStatus.PAM_SUCCESS) throw new InvalidOperationException($"pam_acct_mgmt failed with {lastReturnedValue}");
            }
            finally
            {
                Pam.pam_end(pamHandle, lastReturnedValue);
            }
        }

        ///<summary>
        /// Gets information on the specified user such as real name, shell and home directory.
        /// http://linux.die.net/man/3/getpwnam
        ///</summary>
        public static AccountInfo GetAccountInfo(string user) {
            return StdLibC.GetPwNamAsAccountInfo(user);
        }

        internal class ConversationHandler {

            private string password;

            public ConversationHandler(string password) {
                this.password = password;
            }

            public PamStatus HandlePamConversation(int messageCount, IntPtr messageArrayPtr, ref IntPtr responseArrayPtr,  IntPtr appDataPtr) {
                if (messageCount <= 0) return PamStatus.PAM_CONV_ERR;
                var messages = MarshalUtils.MarshalPtrPtrStructIn<PamMessage>(messageCount, messageArrayPtr);
                if (messageCount == 1) {
                    responseArrayPtr = MarshalUtils.MarshalPtrStructOut<PamResponse>(new PamResponse(password));
                } else {
                    throw new NotSupportedException("NpamAuthentication does not support PAM modules which require responses to multiple conversational messages. Please use NpamSession instead.");
                }

                return PamStatus.PAM_SUCCESS;
            }
        }
        
        internal class ConversationHandlerForChangeToken {

            private string _password;

            public ConversationHandlerForChangeToken(string password) {
                this._password = password;
            }

            public PamStatus HandlePamConversation(int messageCount, IntPtr messageArrayPtr, ref IntPtr responseArrayPtr,  IntPtr appDataPtr)
            {
                if (string.IsNullOrEmpty(this._password)) throw new ArgumentException(nameof(_password));
                
                if (messageCount <= 0) return PamStatus.PAM_CONV_ERR;
                
                var messages = MarshalUtils.MarshalPtrPtrStructIn<PamMessage>(messageCount, messageArrayPtr);
                var responses = new List<PamResponse>();
                
                foreach (var pamMessage in messages)
                {
                    switch (pamMessage.MsgStyle)
                    {
                        case MessageStyle.PAM_PROMPT_ECHO_ON:
                            throw new InvalidOperationException("PAM modules requesting echoing are not supported.");
                        case MessageStyle.PAM_PROMPT_ECHO_OFF:
                            responses.Add(new PamResponse(_password));
                            break;
                        case MessageStyle.PAM_ERROR_MSG:
                            // todo: notify error
                            responses.Add(new PamResponse(null));
                            break;
                        case MessageStyle.PAM_TEXT_INFO:
                            responses.Add(new PamResponse(null));
                            break;
                        default:
                            throw new InvalidOperationException(
                                $"conversation type {pamMessage.MsgStyle} not supported");
                    }
                }
                
                responseArrayPtr = MarshalUtils.MarshalPtrPtrStructOut<PamResponse>(responses);
             
                return PamStatus.PAM_SUCCESS;
            }
        }
    }
}
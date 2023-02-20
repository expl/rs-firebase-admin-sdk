use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum OobCodeActionType {
    #[serde(rename = "VERIFY_EMAIL")]
    VerifyEmail,
    #[serde(rename = "EMAIL_SIGNIN")]
    EmailSignin,
    #[serde(rename = "PASSWORD_RESET")]
    PasswordReset,
    #[serde(rename = "RECOVER_EMAIL")]
    RecoverEmail,
}

#[derive(Serialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct OobCodeAction {
    request_type: Option<OobCodeActionType>,
    email: Option<String>,
    return_oob_link: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    continue_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    can_handle_code_in_app: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dynamic_link_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ios_bundle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    android_package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    android_minimum_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    android_install_app: Option<bool>,
}

impl OobCodeAction {
    pub fn builder(action_type: OobCodeActionType, email: String) -> OobCodeActionBuilder {
        OobCodeActionBuilder::new(action_type, email)
    }
}

#[derive(Debug, Clone)]
pub struct OobCodeActionBuilder {
    action: OobCodeAction,
}

impl OobCodeActionBuilder {
    pub fn new(action_type: OobCodeActionType, email: String) -> Self {
        Self {
            action: OobCodeAction {
                request_type: Some(action_type),
                email: Some(email),
                return_oob_link: Some(true),
                ..Default::default()
            },
        }
    }

    pub fn with_continue_url(mut self, continue_url: String) -> Self {
        self.action.continue_url = Some(continue_url);

        self
    }

    pub fn with_ios_settings(mut self, continue_url: String, bundle_id: String) -> Self {
        self.action.continue_url = Some(continue_url);
        self.action.ios_bundle_id = Some(bundle_id);
        self.action.can_handle_code_in_app = Some(true);

        self
    }

    pub fn with_android_settings(
        mut self,
        continue_url: String,
        android_package_name: String,
        android_minimum_version: Option<String>,
        android_install_app: Option<bool>,
    ) -> Self {
        self.action.continue_url = Some(continue_url);
        self.action.android_package_name = Some(android_package_name);
        self.action.android_minimum_version = android_minimum_version;
        self.action.android_install_app = android_install_app;
        self.action.can_handle_code_in_app = Some(true);

        self
    }

    pub fn build(self) -> OobCodeAction {
        self.action
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OobCodeActionLink {
    pub oob_link: String,
}

//! Email template management and rendering.

use crate::errors::AuthError;
use crate::types::AuthResult;
use std::collections::HashMap;
use tera::{Context, Tera};

/// Email template data for rendering.
#[derive(Debug, Clone)]
pub struct EmailTemplate {
    /// Subject line template
    pub subject: String,
    /// HTML body template
    pub html_body: String,
    /// Plain text body template (optional)
    pub text_body: Option<String>,
}

/// Template variables for email rendering.
#[derive(Debug, Clone)]
pub struct TemplateContext {
    /// User's display name or email
    pub user_name: String,
    /// User's email address
    pub user_email: String,
    /// Verification or reset URL
    pub action_url: String,
    /// Application name
    pub app_name: String,
    /// Token expiration time (human readable)
    pub expiration_time: String,
    /// Additional custom variables
    pub custom_vars: HashMap<String, String>,
}

impl TemplateContext {
    /// Creates a new template context.
    ///
    /// # Arguments
    ///
    /// * `user_name` - User's display name or email
    /// * `user_email` - User's email address
    /// * `action_url` - The URL for the email action (verification, reset, etc.)
    /// * `app_name` - Name of your application
    /// * `expiration_time` - Human-readable expiration time
    #[must_use]
    pub fn new(
        user_name: impl Into<String>,
        user_email: impl Into<String>,
        action_url: impl Into<String>,
        app_name: impl Into<String>,
        expiration_time: impl Into<String>,
    ) -> Self {
        Self {
            user_name: user_name.into(),
            user_email: user_email.into(),
            action_url: action_url.into(),
            app_name: app_name.into(),
            expiration_time: expiration_time.into(),
            custom_vars: HashMap::new(),
        }
    }

    /// Adds a custom variable to the template context.
    #[must_use]
    pub fn with_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom_vars.insert(key.into(), value.into());
        self
    }

    /// Converts to Tera context for template rendering.
    pub(crate) fn to_tera_context(&self) -> Context {
        let mut context = Context::new();
        context.insert("user_name", &self.user_name);
        context.insert("user_email", &self.user_email);
        context.insert("action_url", &self.action_url);
        context.insert("app_name", &self.app_name);
        context.insert("expiration_time", &self.expiration_time);

        for (key, value) in &self.custom_vars {
            context.insert(key, value);
        }

        context
    }
}

/// Template engine for rendering emails.
#[derive(Clone)]
pub struct EmailTemplateEngine {
    tera: Tera,
}

impl EmailTemplateEngine {
    /// Creates a new template engine with default templates.
    ///
    /// # Errors
    ///
    /// Returns an error if template compilation fails.
    pub fn new() -> AuthResult<Self> {
        let mut tera = Tera::default();

        // Add default templates
        let templates = vec![
            ("email_verification_subject", DEFAULT_VERIFICATION_SUBJECT),
            ("email_verification_html", DEFAULT_VERIFICATION_HTML),
            ("email_verification_text", DEFAULT_VERIFICATION_TEXT),
            ("password_reset_subject", DEFAULT_PASSWORD_RESET_SUBJECT),
            ("password_reset_html", DEFAULT_PASSWORD_RESET_HTML),
            ("password_reset_text", DEFAULT_PASSWORD_RESET_TEXT),
        ];

        for (name, template) in templates {
            tera.add_raw_template(name, template)
                .map_err(|e| AuthError::TemplateError {
                    message: format!("Failed to compile template '{name}': {e}"),
                })?;
        }

        Ok(Self { tera })
    }

    /// Creates a template engine with a simple map of custom templates.
    ///
    /// # Arguments
    ///
    /// * `templates` - `HashMap` of template names to template content
    ///
    /// # Errors
    ///
    /// Returns an error if any template compilation fails.
    pub fn with_template_map(templates: HashMap<String, String>) -> AuthResult<Self> {
        let mut tera = Tera::default();

        for (name, template) in templates {
            tera.add_raw_template(&name, &template)
                .map_err(|e| AuthError::TemplateError {
                    message: format!("Failed to compile template '{name}': {e}"),
                })?;
        }

        Ok(Self { tera })
    }

    /// Creates a template engine with custom templates for verification and password reset.
    ///
    /// # Arguments
    ///
    /// * `verification_templates` - Optional custom verification templates (subject, html, text)
    /// * `reset_templates` - Optional custom password reset templates (subject, html, text)
    /// * `custom_templates` - Additional custom templates
    ///
    /// # Errors
    ///
    /// Returns an error if any template compilation fails.
    pub fn with_custom_templates(
        verification_templates: Option<&(String, String, Option<String>)>,
        reset_templates: Option<&(String, String, Option<String>)>,
        custom_templates: HashMap<String, String>,
    ) -> AuthResult<Self> {
        let mut tera = Tera::default();

        // Add default or custom verification templates
        let (verification_subject, verification_html, verification_text) =
            verification_templates.as_ref().map_or(
                (
                    DEFAULT_VERIFICATION_SUBJECT,
                    DEFAULT_VERIFICATION_HTML,
                    DEFAULT_VERIFICATION_TEXT,
                ),
                |(s, h, t)| {
                    (
                        s.as_str(),
                        h.as_str(),
                        t.as_deref().unwrap_or(DEFAULT_VERIFICATION_TEXT),
                    )
                },
            );

        // Add default or custom password reset templates
        let (reset_subject, reset_html, reset_text) = reset_templates.as_ref().map_or(
            (
                DEFAULT_PASSWORD_RESET_SUBJECT,
                DEFAULT_PASSWORD_RESET_HTML,
                DEFAULT_PASSWORD_RESET_TEXT,
            ),
            |(s, h, t)| {
                (
                    s.as_str(),
                    h.as_str(),
                    t.as_deref().unwrap_or(DEFAULT_PASSWORD_RESET_TEXT),
                )
            },
        );

        // Compile all templates
        let templates = vec![
            ("email_verification_subject", verification_subject),
            ("email_verification_html", verification_html),
            ("email_verification_text", verification_text),
            ("password_reset_subject", reset_subject),
            ("password_reset_html", reset_html),
            ("password_reset_text", reset_text),
        ];

        for (name, template) in templates {
            tera.add_raw_template(name, template)
                .map_err(|e| AuthError::TemplateError {
                    message: format!("Failed to compile template '{name}': {e}"),
                })?;
        }

        // Add any additional custom templates
        for (name, template) in custom_templates {
            tera.add_raw_template(&name, &template)
                .map_err(|e| AuthError::TemplateError {
                    message: format!("Failed to compile custom template '{name}': {e}"),
                })?;
        }

        Ok(Self { tera })
    }

    /// Renders an email verification template.
    ///
    /// # Arguments
    ///
    /// * `context` - Template context with variables
    ///
    /// # Errors
    ///
    /// Returns an error if template rendering fails.
    pub fn render_email_verification(
        &self,
        context: &TemplateContext,
    ) -> AuthResult<EmailTemplate> {
        let tera_context = context.to_tera_context();

        let subject = self
            .tera
            .render("email_verification_subject", &tera_context)
            .map_err(|e| AuthError::TemplateError {
                message: format!("Failed to render email verification subject: {e}"),
            })?;

        let html_body = self
            .tera
            .render("email_verification_html", &tera_context)
            .map_err(|e| AuthError::TemplateError {
                message: format!("Failed to render email verification HTML: {e}"),
            })?;

        let text_body = self
            .tera
            .render("email_verification_text", &tera_context)
            .map_err(|e| AuthError::TemplateError {
                message: format!("Failed to render email verification text: {e}"),
            })?;

        Ok(EmailTemplate {
            subject,
            html_body,
            text_body: Some(text_body),
        })
    }

    /// Renders a password reset template.
    ///
    /// # Arguments
    ///
    /// * `context` - Template context with variables
    ///
    /// # Errors
    ///
    /// Returns an error if template rendering fails.
    pub fn render_password_reset(&self, context: &TemplateContext) -> AuthResult<EmailTemplate> {
        let tera_context = context.to_tera_context();

        let subject = self
            .tera
            .render("password_reset_subject", &tera_context)
            .map_err(|e| AuthError::TemplateError {
                message: format!("Failed to render password reset subject: {e}"),
            })?;

        let html_body = self
            .tera
            .render("password_reset_html", &tera_context)
            .map_err(|e| AuthError::TemplateError {
                message: format!("Failed to render password reset HTML: {e}"),
            })?;

        let text_body = self
            .tera
            .render("password_reset_text", &tera_context)
            .map_err(|e| AuthError::TemplateError {
                message: format!("Failed to render password reset text: {e}"),
            })?;

        Ok(EmailTemplate {
            subject,
            html_body,
            text_body: Some(text_body),
        })
    }

    /// Adds a custom template to the engine.
    ///
    /// # Arguments
    ///
    /// * `name` - Template name
    /// * `content` - Template content (Tera syntax)
    ///
    /// # Errors
    ///
    /// Returns an error if template compilation fails.
    pub fn add_template(&mut self, name: &str, content: &str) -> AuthResult<()> {
        self.tera
            .add_raw_template(name, content)
            .map_err(|e| AuthError::TemplateError {
                message: format!("Failed to add template '{name}': {e}"),
            })
    }

    /// Renders a custom template.
    ///
    /// # Arguments
    ///
    /// * `template_name` - Name of the template to render
    /// * `context` - Template context with variables
    ///
    /// # Errors
    ///
    /// Returns an error if template rendering fails.
    pub fn render_custom(
        &self,
        template_name: &str,
        context: &TemplateContext,
    ) -> AuthResult<String> {
        let tera_context = context.to_tera_context();

        self.tera
            .render(template_name, &tera_context)
            .map_err(|e| AuthError::TemplateError {
                message: format!("Failed to render template '{template_name}': {e}"),
            })
    }
}

impl Default for EmailTemplateEngine {
    fn default() -> Self {
        Self::new().unwrap_or_default()
    }
}

// Default email verification templates
const DEFAULT_VERIFICATION_SUBJECT: &str = "Verify your email address for {{ app_name }}";

const DEFAULT_VERIFICATION_HTML: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #007bff; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background-color: #f8f9fa; padding: 30px; border-radius: 0 0 8px 8px; }
        .button { display: inline-block; background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ app_name }}</h1>
    </div>
    <div class="content">
        <h2>Verify Your Email Address</h2>
        <p>Hello {{ user_name }},</p>
        <p>Thank you for signing up for {{ app_name }}! To complete your registration, please verify your email address by clicking the button below:</p>
        <p style="text-align: center;">
            <a href="{{ action_url }}" class="button">Verify Email Address</a>
        </p>
        <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
        <p><a href="{{ action_url }}">{{ action_url }}</a></p>
        <p>This verification link will expire in {{ expiration_time }}.</p>
        <p>If you didn't create an account with {{ app_name }}, you can safely ignore this email.</p>
    </div>
    <div class="footer">
        <p>This email was sent to {{ user_email }}. If you have any questions, please contact our support team.</p>
    </div>
</body>
</html>
"#;

const DEFAULT_VERIFICATION_TEXT: &str = r"
{{ app_name }} - Verify Your Email Address

Hello {{ user_name }},

Thank you for signing up for {{ app_name }}! To complete your registration, please verify your email address by visiting this link:

{{ action_url }}

This verification link will expire in {{ expiration_time }}.

If you didn't create an account with {{ app_name }}, you can safely ignore this email.

This email was sent to {{ user_email }}. If you have any questions, please contact our support team.
";

// Default password reset templates
const DEFAULT_PASSWORD_RESET_SUBJECT: &str = "Reset your password for {{ app_name }}";

const DEFAULT_PASSWORD_RESET_HTML: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #dc3545; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background-color: #f8f9fa; padding: 30px; border-radius: 0 0 8px 8px; }
        .button { display: inline-block; background-color: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ app_name }}</h1>
    </div>
    <div class="content">
        <h2>Reset Your Password</h2>
        <p>Hello {{ user_name }},</p>
        <p>We received a request to reset the password for your {{ app_name }} account. Click the button below to reset your password:</p>
        <p style="text-align: center;">
            <a href="{{ action_url }}" class="button">Reset Password</a>
        </p>
        <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
        <p><a href="{{ action_url }}">{{ action_url }}</a></p>
        <div class="warning">
            <strong>Security Notice:</strong> This password reset link will expire in {{ expiration_time }}. If you didn't request a password reset, please ignore this email and your password will remain unchanged.
        </div>
        <p>For security reasons, we recommend choosing a strong, unique password that you haven't used elsewhere.</p>
    </div>
    <div class="footer">
        <p>This email was sent to {{ user_email }}. If you have any questions or concerns, please contact our support team immediately.</p>
    </div>
</body>
</html>
"#;

const DEFAULT_PASSWORD_RESET_TEXT: &str = r"
{{ app_name }} - Reset Your Password

Hello {{ user_name }},

We received a request to reset the password for your {{ app_name }} account. Visit this link to reset your password:

{{ action_url }}

SECURITY NOTICE: This password reset link will expire in {{ expiration_time }}. If you didn't request a password reset, please ignore this email and your password will remain unchanged.

For security reasons, we recommend choosing a strong, unique password that you haven't used elsewhere.

This email was sent to {{ user_email }}. If you have any questions or concerns, please contact our support team immediately.
";

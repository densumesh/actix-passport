// @generated automatically by Diesel CLI.

diesel::table! {
    users (id) {
        id -> Uuid,
        email -> Nullable<Varchar>,
        username -> Nullable<Varchar>,
        display_name -> Nullable<Varchar>,
        avatar_url -> Nullable<Varchar>,
        password_hash -> Nullable<Varchar>,
        created_at -> Timestamptz,
        last_login -> Nullable<Timestamptz>,
        metadata -> Jsonb,
        oauth_providers -> Jsonb,
    }
}
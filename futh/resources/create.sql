drop schema if exists public cascade;
create schema public;

set search_path = postgres,public;

create table users
(
    id          serial primary key not null,
    username    varchar unique     not null,
    password    bytea              not null,
    role        varchar,

    -- metadata
    insert_date timestamp default now(),
    delete_date timestamp
);

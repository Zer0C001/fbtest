create table suggestions (
 id bigint PRIMARY KEY,
 creator_id bigint,
 category_id bigint,
 created_time timestamp,
 pos_votes bigint,
 neg_votes bigint,
 closed boolean
);
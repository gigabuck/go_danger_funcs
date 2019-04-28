CREATE TABLE files ( 
	file_id              integer NOT NULL  ,
	file                 varchar(256)   ,
	CONSTRAINT Pk_files_file_id PRIMARY KEY ( file_id )
 );

CREATE TABLE findings ( 
	findings_id          integer NOT NULL  ,
	file_id              integer   ,
	name                 varchar(100)   ,
	desc                 varchar(100)   ,
	pattern              varchar(100)   ,
	line                 blob   ,
	line_no              integer   ,
	col                integer   ,
	CONSTRAINT Pk_findings_findings PRIMARY KEY ( findings_id ),
	FOREIGN KEY ( file_id ) REFERENCES files( file_id )  
 );


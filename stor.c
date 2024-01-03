#include<stdio.h>
#include<stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/evp.h>


enum Mode {Read=0, Write=1, Register=2, Create=3};


int mode = -1;


#define MAX_FILE 100


#define BUFF_SIZE 4096


#define MAX_USER 256


#define MAX_KEY 256


char filename[MAX_FILE];


char inputfile[MAX_FILE];


char outputfile[MAX_FILE];


char username[MAX_USER];
char hashedusername[MAX_USER];


char key[MAX_KEY];
char hashedkey[MAX_KEY];


char *text;
char *encryptedtext;


int input_fd = STDIN_FILENO;


int output_fd = STDOUT_FILENO;


typedef struct file {
	size_t next_filesize;
	char filename[256];
	struct file *next;
	size_t filelength;
	size_t encryptedcount;
	char content[0];
} file_t;


typedef struct user {
	char username[256];
	char key[256];
	struct user *next;
	size_t first_filesize;
	file_t *file;
} user_t;




user_t *list_start;	


user_t *list_end;	

/**
 * @brief Win function
 */
void win() {
	printf("Arbitrary access achieved!\n");
}

/**
 * @brief Check if username and key is provided
 */
void check_credentials_exist() {
	if (strlen(username)==0 || strlen(key)==0){
		printf("Error: username/secretkey pair not provided\n");
		exit(0);
	}
}

/**
 * @brief Free user linked list and file linked lists
 */
void cleanup_memory() {
	
	user_t *current_user = list_start;
	user_t *temp_user;

	file_t *current_file;
	file_t *temp_file;

	
	while (current_user != NULL) {
		temp_user = current_user;
		current_user = current_user->next;

		
		current_file = temp_user->file;
		while (current_file != NULL) {
			temp_file = current_file;
			current_file = current_file->next;
			free(temp_file);
		}
		free(temp_user);
	}
	list_start = NULL;
}

/**
 * @brief Prints command line options for the file storage system
 */
void print_options(){
	printf("Usage: ./stor -u <username> -k <secretkey> [read|write|register|create] -f <filename> -i <inputfile> -o <outputfile> <text>\n\
       ./stor -h\n\
           \n\
    -h          	Print this help message and exit\n\
    -u <username>	Username used to authenticate/register the user\n\
    -k <secretkey>  Secret token used to authenticate/register the user\n\
    read      		Read contents of file stored in encrypted filesystem\n\
	write      		Write contents to a file in encrypted filesystem\n\
	register      	Used with username and key to register the user\n\
	create      	Used with username and filename to create file in encrypted filesystem\n\
    -f <filename>   Filename in encrypted filesystem\n\
    -i <inputfile>  Takes input from an existing file on file system.\n\
	-o <outputfile> Output is written to a file on file system\n\
	text 			The inline input for when -i is absent\n\
    \n\
	\n");
    return;
}
/**
 * @brief hash function
 * @cite https:
 */
char * hashit(char * input, char * hashoutput){
	size_t          i;					       
	char            buff[4096];	       
	unsigned int    md_len;				       
	EVP_MD_CTX      *mdctx;				       
	unsigned char md_value[EVP_MAX_MD_SIZE];   

	mdctx = EVP_MD_CTX_new();
	const EVP_MD *EVP_sha256();   

	EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);	   
	EVP_DigestUpdate(mdctx, input, strlen(input));
	EVP_DigestFinal_ex(mdctx, hashoutput, &md_len);
	hashoutput[md_len]='\0';	
}

void handleErrors(){
	printf("Encryption/Decryption error!\n");
	exit(1);
}

/**
 * @brief encryption function
 * @cite https:
 */
int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


   
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

   
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

   
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

   
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

   
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

   
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

   
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;
	

   
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

   
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/**
 * @brief decryption function
 * @cite https:
 */
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

   
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

   
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

   
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

   
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

   
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

   
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

   
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

   
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

   
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
       
        plaintext_len += len;
        return plaintext_len;
    } else {
       
        return -1;
    }
}


void print_file(file_t * file) {
	printf("Filename: %s\n", file->filename);
	printf("File size: %zu\n", file->next_filesize);
	printf("Content: %s\n", file->content);
}


void print_user(user_t * user) {
	printf("Username: %s\n", user->username);
	printf("Key: %s\n", user->key);
	printf("First File Size: %zu\n", user->first_filesize);

	file_t *file = user->file;
	while (file != NULL){
		print_file(file);
		file = file->next;
	}
	printf("\n");
}

void print_user_list() {
	user_t * user = list_start;
	printf("\n-----------------------------------------------\n");
	printf("Printing User List:\n");
	while (user != NULL) {
		print_user(user);
		user = user->next;
	}
}

void print_db() {
	user_t input_user;
	file_t input_file;

	FILE *infile = fopen("enc.db", "r");

	if (infile == NULL)
    {
        fprintf(stderr, "\nError opening file\n");
        exit (1);
    }

	printf("Printing DB...................\n");

    while(fread(&input_user, sizeof(user_t), 1, infile))
        printf ("Name = %s Key = %s \n", input_user.username, input_user.key);

		if (input_user.file != NULL) {
			fread(&input_file, input_user.first_filesize, 1, infile);
			printf("Filename: %s Content: %s\n",
				input_file.filename,
				input_file.content
			);
			while (input_file.next != NULL){
				fread(&input_file, input_file.next_filesize, 1, infile);
				printf("Filename: %s Content: %s\n",
					input_file.filename,
					input_file.content
				);
			}
		}

    fclose (infile);
}

void write_encrypted(file_t *new_file){

	char plainuserkey[2*MAX_KEY]; 
	char hasheduserkey[MAX_KEY]; 
	strncat(plainuserkey, username, strlen(username));
	strncat(plainuserkey, key, strlen(key));
	hashit(plainuserkey, hasheduserkey);
	
	
	char ciphertext[BUFF_SIZE];
	char tag[BUFF_SIZE]; 
	char decryptedtext[BUFF_SIZE];
	int encryptedlength;
	
	
	encryptedlength = gcm_encrypt(text, strlen(text), NULL, 0, hasheduserkey, plainuserkey, strlen(plainuserkey), ciphertext, tag);

	strncpy(new_file->filename, filename, MAX_USER);
	strncpy(new_file->content, ciphertext, encryptedlength);
	
	new_file->filelength = strlen(text);
	new_file->encryptedcount = encryptedlength;
}

void output_read_encrypted(file_t *target_file){

	char plainuserkey[2*MAX_KEY]; 
	char hasheduserkey[MAX_KEY]; 
	strncat(plainuserkey, username, MAX_KEY);
	strncat(plainuserkey, key, MAX_KEY);
	hashit(plainuserkey, hasheduserkey);
	
	
	char ciphertext[BUFF_SIZE];
	char tag[BUFF_SIZE]; 
	char decryptedtext[BUFF_SIZE];
	int encryptedlength;

	gcm_decrypt(target_file->content, target_file->encryptedcount, NULL, 0, tag, hasheduserkey, plainuserkey, strlen(plainuserkey), decryptedtext);

	decryptedtext[target_file->filelength]= '\0';
	printf("%s\n", decryptedtext);
}

void insert_user_list(user_t *user) {

	if (list_start == NULL) {
		list_start = user;
		list_end = user;
	}

	else {
		list_end->next = user;
		list_end = user;
	}
}


user_t *find_user(char *input_name, char *input_key) {

	user_t *user = list_start;

	while(user != NULL) {
		
        if (!strncmp(user->username, input_name, strlen(input_name)) && 
			!strncmp(user->key, input_key, strlen(input_key))
		) {
			return user;
		}

		user = user->next;
	}

	
	return NULL;
}


file_t *find_file_with_user(user_t *user, char *file_name){

	file_t *file = user->file;

	while(file!=NULL){
		if (!strncmp(file->filename, file_name, strlen(file_name))){
			return file;
		}
		file = file->next;
	}
	
	
	return NULL;
}


file_t *find_last_file(user_t *user){

	if(user->file==NULL){
		return NULL;
	}

	file_t *file = user->file;

	while(file->next!=NULL){
		file = file->next;
	}

	return file;
}


file_t *find_prev_file(user_t *user, char *file_name){

	file_t *file = user->file;

	if(file == NULL){
		return NULL;
	}

	while(file->next!=NULL){
		if (!strncmp(file->next->filename, file_name, strlen(file_name))){
			return file;
		}
		file = file->next;
	}
	
	
	return NULL;
}


void read_db() {
	user_t stored_user;
	file_t stored_file;

	FILE *infile = fopen("enc.db", "r");

	if (infile == NULL)
    {
		FILE *new_file = fopen("enc.db", "w");
		fclose(new_file);
		return;
    }

    while(fread(&stored_user, sizeof(user_t), 1, infile)) {
		
		user_t *new_user = calloc(1, sizeof(user_t));

		memcpy(new_user, &stored_user, sizeof(user_t));

		if (stored_user.first_filesize > 0) {
			file_t *current_file = calloc(1, stored_user.first_filesize);
			fread(current_file, stored_user.first_filesize, 1, infile);
			new_user->file = current_file;

			
			while(current_file->next_filesize > 0){
				file_t *next_file = calloc(1, current_file->next_filesize);
				fread(next_file, current_file->next_filesize, 1, infile);
				current_file->next = next_file;
				current_file = next_file;
			}
		}

		insert_user_list(new_user);
	}

    fclose (infile);
}


void write_db(){
	FILE *outfile = fopen("enc.db", "w+");
	if (outfile == NULL)
    {
        fprintf(stderr, "\nError opened file\n");
        exit (1);
    }

	user_t * user = list_start;

	while(user != NULL) {
		fwrite(user, sizeof(user_t), 1, outfile);

		file_t * file = user->file;
		size_t file_size = user->first_filesize;

		while(file != NULL){
			fwrite(file, file_size, 1, outfile);
			file_size = file->next_filesize;
			file = file->next;
		}

		user = user->next;
	}
	
	fclose(outfile);
}


void read_file(){
	if(strlen(filename)==0){
		printf("Error: filename not provided\n");
		return;
	}

	file_t *target_file = find_file_with_user(find_user(hashedusername, hashedkey), filename);

	if(target_file==NULL){
		printf("Error: File not found for user\n");
		return;
	}

	if(output_fd==STDOUT_FILENO){
		output_read_encrypted(target_file);
		
	}
	else{
		
		
	}
}


file_t *create_file(){
	if(strlen(filename)==0){
		printf("Error: filename not provided\n");
		return NULL;
	}

	if (find_file_with_user(find_user(hashedusername, hashedkey), filename)!=NULL){
		printf("Error: Duplicated file name\n");
	}

	size_t text_len;

	if(text==NULL){
		text_len = 0;
	} 
	else{
		text_len = strlen(text);
	}

	
	file_t *new_file = calloc(1, sizeof(file_t) + text_len);
	if (new_file == NULL){
		printf("Unable to create file");
		return NULL;
	}

	
	if(text_len >0) {
		write_encrypted(new_file);
	}
	
	
	user_t *target_user = find_user(hashedusername, hashedkey);
	file_t *last_file = find_last_file(target_user);
	if(last_file==NULL){
		target_user->file = new_file;
		target_user->first_filesize = sizeof(file_t) + text_len;
	}
	else{
		last_file->next_filesize = sizeof(file_t) + text_len;
		last_file->next = new_file;
	}

	write_db();

	return NULL;

}


void write_file(char *input_name, char *input_key){
	if(strlen(filename)==0){
		printf("Error: filename not provided\n");
		return;
	}

	user_t *target_user = find_user(input_name, input_key);

	if (target_user == NULL) {
		printf("Error: User not found\n");
		return;
	}

	file_t *target_file = find_file_with_user(target_user, filename);

	if (target_file == NULL) {
		
		create_file();
	}
	else{
		
		write_encrypted(target_file);
		

		
		if (target_file == target_user->file) {
			
			target_user->first_filesize = sizeof(file_t) + strlen(text);
		}
		else{
			file_t *prev_file = find_prev_file(target_user, filename);
			prev_file->next_filesize = sizeof(file_t) + strlen(text);
		}

		write_db();
	}

}


void register_user(){

	if (find_user(hashedusername, hashedkey) == false) {
		user_t * new_user = calloc(1, sizeof(user_t));

		strncpy(new_user->username , hashedusername, MAX_USER);
		strncpy(new_user->key , hashedkey, MAX_USER);
		new_user->first_filesize = 0;
		new_user->next = NULL;
		new_user->file = NULL;

		FILE *outfile = fopen("enc.db", "ab+");
		if (outfile == NULL)
		{
			fprintf(stderr, "\nError opened file\n");
			fclose(outfile);
			exit (1);
		}

		fwrite(new_user, sizeof(user_t), 1, outfile);

		fclose(outfile);

		printf("User %s has been registered\n", username);
	}
	else{
		printf("User already registered\n");
	}
}


int main(int argc, char **argv) {
	
	memset(filename, 0, MAX_FILE);
	memset(inputfile, 0, MAX_FILE);
	memset(outputfile, 0, MAX_FILE);
	memset(username, 0, MAX_USER);
	memset(hashedusername, 0, MAX_USER);
	memset(key, 0, MAX_KEY);
	memset(hashedkey, 0, MAX_KEY);

	int opt;
    while ((opt = getopt(argc, argv, "-hu:k:f:i:o:")) != -1) {
        switch (opt) {
			case 'h':
				print_options();
				return 0;
			case 'u':
				strncpy(username, optarg, MAX_USER);
				hashit(optarg, hashedusername);
				break;
			case 'k':
				strncpy(key, optarg, MAX_KEY);
				hashit(optarg, hashedkey);
				break;
			case 'f':
				strncpy(filename, optarg, MAX_FILE);
				break;
			case 'i':
				strncpy(inputfile, optarg, MAX_FILE);
				break;
			case 'o':
				strncpy(outputfile, optarg, MAX_FILE);
				break;
			case 1:
				if(mode == -1){
					if(!strncmp(optarg, "read", 4)){
						mode = Read;
						break;
					}
					if(!strncmp(optarg, "write", 5)){
						mode = Write;
						break;
					}
					if(!strncmp(optarg, "register", 8)){
						mode = Register;
						break;
					}
					if(!strncmp(optarg, "create", 6)){
						mode = Create;
						break;
					}
					
					text = calloc(1, strlen(optarg)+1);
					strncpy(text, optarg, strlen(optarg));
					break;
				}
				
				text = calloc(1, strlen(optarg)+1);
				strncpy(text, optarg, strlen(optarg));
				break;
			default:
				print_options();
				return 1;
        }
    }

	read_db();


	switch (mode) {
		case Read:
			check_credentials_exist();
			if (find_user(hashedusername, hashedkey) != NULL) {
				read_file();
			}
			else {
				printf("User not Found, please register\n");
			}
			break;

		case Write:
			check_credentials_exist();
			write_file(hashedusername, hashedkey);

			printf("Data written to %s by %s\n", filename, username);
			break;
			
		case Register:
			check_credentials_exist();
			register_user();
			break;
			
		case Create:
			if (strlen(username)==0){
				printf("Error: username not provided\n");
				return 0;
			}
			create_file();

			printf("%s has been created for %s\n", filename, username);
			break;
		default:
			printf("Error: Mode not specified\n");
			return 1;
	}

	

	cleanup_memory();

	return 0;
}

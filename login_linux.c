/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */
/* Group 20*/
/*Miranda Jernberg*/
/*Malin Dahlén*/

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>


/* Uncomment next line in step 2 */
#include "pwent.h" 

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler() {

	signal(SIGINT, SIG_IGN);  /* Ignores interactive attention signals such as ctrl+c. */
	signal(SIGQUIT, SIG_IGN); /* Ignores quit from keyborad. */
	
}

int main(int argc, char *argv[]) {
	mypwent *passwddata;


	/*struct passwd *passwddata; this has to be redefined in step 2 */
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];
	

	char important2[LENGTH] = "**IMPORTANT 2**"; 

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;
	

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user,LENGTH,stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */

		user[strlen(user)-1] = '\0';

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		
		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);


		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */
			char *encryption = crypt(user_pass,passwddata->passwd_salt);


			
			if(!strcmp(encryption, passwddata->passwd) && passwddata->pwfailed <= 3){  

				printf(" You're in !\n"); /* Successful login */

				passwddata->pwage++;     /* Increment the age of the password */


				printf("Number of failed attempts: %d\n", passwddata->pwfailed);   /*Print the number of failed attempts*/
				passwddata->pwfailed = 0;                     /*Reset the counter */

				if(passwddata->pwage > 5){                  /*If the age of the password is older than 5*/

					printf("You have passed 5 logins, do you want to change password?(y) \n");       /*print a reminder*/
					char answer[2];
					if(fgets(answer,2 , stdin)==NULL)     /*Get answer and make sure it is not NULL*/
						exit(255);

					if(answer[0] == 'y'){               /*If yes, enter new password*/
						char *password;
						password = getpass("Enter new password:");
					
						if(password == NULL){                      /*Make sure new password is not NULL*/
							bzero(password,8);
							printf("Invalid password");
						}
						passwddata->passwd = crypt(password, passwddata->passwd_salt);      /*Crypt new password*/						
						passwddata->pwage = 0;
						
					}

				}


				if(mysetpwent(user,passwddata)==-1) {         /*Try to save changes to database*/
					printf("No access to database");
					exit(0);
					}

				/*  check UID, see setuid(2) */
				
				if(setuid(passwddata->uid)==-1){
					printf("Error, can not check ID");
					exit(0);
				}

			
				/*  start a shell, use execve(2) */
				char *argv[] = {"/bin/sh", NULL};
				char *envp[] = {NULL};

				if(execve("/bin/sh", argv, envp)==-1){
					printf("Error, can not start a shell");
					exit(0);
				}

			/*If login fails*/
			}else{
 
				passwddata->pwfailed++;     /*Increment number of fails*/

				if(mysetpwent(user,passwddata)==-1)    /*Try to update database*/
					printf("No access to database");

			
			}
		}
		printf("Login Incorrect \n");
		
		

	}
	return 0;
}

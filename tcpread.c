#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/poll.h>
#include <signal.h>
 
#define BUFFER_LENGTH 1024

static char receive[BUFFER_LENGTH];
static int keepRunning = 1;
struct pollfd pofd;

void intHandler(int dummy) {
   keepRunning = 0;
   printf("cleaning out my closet.\n");
   close(pofd.fd);
}

int main(){
   int ret;

   if(!(pofd.fd = open("/dev/sniffa", O_RDONLY | O_NONBLOCK))) {
      printf("Failed to open up the desc.\n");
      return -1;
   }   
   printf("Device is opened.\n");

   pofd.events = POLLIN;
   pofd.revents = 0;

   signal(SIGINT, intHandler);

   printf("[IFACE, LEN, S_PORT, D_PORT, S_ADDR, D_ADDR]\n");

   while(keepRunning) {
      ret = poll(&pofd, 1, -1);

      if (ret < 0) {
         printf("Poll failed with : %d\n", ret);
         return ret;
      }
      if (pofd.revents | POLLIN) {
         ret = read(pofd.fd, receive, BUFFER_LENGTH);
         if (ret < 0){
            printf("Failed to read the message from the device.\n");
            return ret;
         }
         printf("[%s]\n", receive);
      }
   }

   return 0;
}
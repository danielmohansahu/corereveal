#include <stdlib.h>
#include <stdio.h>
#include <string.h>

unsigned int seed;
unsigned int max_retries;
unsigned int max_value; 

void init_vars()
{
    // Dynamically Loaded in Variables
    seed = (0xdead << 16) | 0xbeef;
    max_retries = 5;
    max_value = 1000;
}

int get_guess()
{
    int guess;

    scanf("%d", &guess);
    return guess;
}

int main()
{
    init_vars();

    int number;
    int guess;
    int count = 0;

    srand(seed);

    printf("I'm thinking of a number between 0 and %d\n", max_value);
    printf("Can you guess it?\n");

    number = rand() % (max_value + 1);

    while (count < max_retries)
    {
        count++;
        guess = get_guess();

        if (guess == number)
        {
            printf("Wow you got it!\n");
            return 0;
        }
        else if(guess > number)
        {
            printf("A little too high.\n");
        }
        else
        {
            printf("Too Low.\n");
        }
        
    }
    return 1;
    
}
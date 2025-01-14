---
layout: writeup
category: Iris-CTF-2024
chall_description:
points: 50
solves: 316
tags: rev rev/logic
date: 2024-1-7
comments: false
---

Please socialize with the Johnson's and get off your phone. You might be quizzed on it!  
`nc babyrevjohnson.chal.irisc.tf 10002`  
[babyrevjohnson.tar.gz](https://github.com/Nightxade/ctf-writeups/blob/master/assets/CTFs/Iris-CTF-2024/babyrevjohnson.tar.gz)  

---

Decompile in Ghidra. Here's the two relevant functions, `main` and `check` with my edited variable names.  

```c
undefined8 main(void)

{
  int choice;
  long in_FS_OFFSET;
  int index;
  int color_choice;
  int food_choice;
  char input [104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Welcome to the Johnson\'s family!");
  puts(
      "You have gotten to know each person decently well, so let\'s see if you remember all of the f acts."
      );
  puts("(Remember that each of the members like different things from each other.)");
  index = 0;
  while (index < 4) {
    printf("Please choose %s\'s favorite color: ",*(undefined8 *)(names + (long)index * 8));
    __isoc99_scanf(&fmt_99chars,input);
    choice = strcmp(input,red_ptr);
    if (choice == 0) {
      color_choice = 1;
LAB_set_and_check_color:
      if ((((color_choice == color1) || (color_choice == color2)) || (color_choice == color3)) ||
         (color_choice == color4)) {
        puts("That option was already chosen!");
      }
      else {
        (&color1)[index] = color_choice;
        index = index + 1;
      }
    }
    else {
      choice = strcmp(input,blue_ptr);
      if (choice == 0) {
        color_choice = 2;
        goto LAB_set_and_check_color;
      }
      choice = strcmp(input,green_ptr);
      if (choice == 0) {
        color_choice = 3;
        goto LAB_set_and_check_color;
      }
      choice = strcmp(input,yellow_ptr);
      if (choice == 0) {
        color_choice = 4;
        goto LAB_set_and_check_color;
      }
      puts("Invalid color!");
    }
  }
  index = 0;
  do {
    while( true ) {
      if (3 < index) {
        check();
        if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
          __stack_chk_fail();
        }
        return 0;
      }
      printf("Please choose %s\'s favorite food: ",*(undefined8 *)(names + (long)index * 8));
      __isoc99_scanf(&fmt_99chars,input);
      choice = strcmp(input,pizza_ptr);
      if (choice != 0) break;
      food_choice = 1;
LAB_set_and_check_food:
      if (((food_choice == food1) || (food_choice == food2)) ||
         ((food_choice == food3 || (food_choice == food4)))) {
        puts("That option was already chosen!");
      }
      else {
        (&food1)[index] = food_choice;
        index = index + 1;
      }
    }
    choice = strcmp(input,pasta_ptr);
    if (choice == 0) {
      food_choice = 2;
      goto LAB_set_and_check_food;
    }
    choice = strcmp(input,steak_ptr);
    if (choice == 0) {
      food_choice = 3;
      goto LAB_set_and_check_food;
    }
    choice = strcmp(input,chicken_ptr);
    if (choice == 0) {
      food_choice = 4;
      goto LAB_set_and_check_food;
    }
    puts("Invalid food!");
  } while( true );
}

void check(void)

{
  bool bool1;
  byte bool2;
  
  if ((food3 == 2) || (food4 == 2)) {
    bool1 = false;
  }
  else {
    bool1 = true;
  }
  if ((color1 == 3) || (color2 == 3)) {
    bool2 = 0;
  }
  else {
    bool2 = 1;
  }
  if (color4 == 2 &&
      (color3 != 4 && (food4 != 3 && (food1 == 4 && (bool)((color2 != 1 && bool1) & bool2))))) {
    puts("Correct!");
    system("cat flag.txt");
  }
  else {
    puts("Incorrect.");
  }
  return;
}
```

From this, we can very easily outline certain constraints based on the `check()` function. See below, where `=` represents the correct one, while `!` represents what it cannot be.  
```py
Constraints:
            1   2   3   4
    colors
        1   =       !
        2   !       !   =
        3           =   !
        4       =
    foods
        1               =
        2       =
        3       !   =
        4   =   !   !
```

Therefore, these are the following orders:  

Colors: 1 4 3 2 ==> red yellow green blue  
Foods: 4 2 3 1 ==> chicken pasta steak pizza  

Connect to the service and send the input to get the flag!  

    irisctf{m0r3_th4n_0n3_l0g1c_puzzl3_h3r3}
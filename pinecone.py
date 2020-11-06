#!/usr/bin/env python3

import argparse
import sys

from prompt_toolkit.formatted_text import HTML
from prompt_toolkit import print_formatted_text

from pinecone.core.database import init_database
from pinecone.core.main import Pinecone

if __name__ == "__main__":
    # TODO: reset styling for version.
    pinecone_logo = '''<p fg="#878787">
                ▐                                                  
                █                                                  
               ▐█                                                  
         ▄     ██      ▄█                                          
         ██▄   ▐█     ███          ▄▀▀▀▀▀▄                         
         ▐███▄  █   ▄██▀          ▀ ▄▀▀▀▄ ▀                        
      ▄   ▀▀███▄▐ ▄▀▀▀    ▄           ▀                            
      ██▄    ▀▀▀█▌     ▄███      █▀█  █  █ █  █▀  █▀█  ▐▀▌  █ █  █▀
   ▄  ▀████▄     ▀▀▄▄███▀▀    ▄  █ █  █  █▌█  █▄  █ ▀  █ █  █▌█  █▄
  ▐██▄▄  ▀▀██▄▄  ▄█▀▀       ▄██  █▀▀  █  █▐█  █   █ ▄  █ █  █▐█  █ 
  ▐█████▄    ▀▀█▄        ▄█████  █    █  █ █  █▄  █▄█  ▐▄▌  █ █  █▄
   ▀██████▄      ▀▄▄  ▄██████▀                                     
█▄▄   ▀▀█████▄     ▄▄██▀▀▀▀      ▄█                          <p fg="ansiwhite">v0.2.0</p>
████▄▄    ▀▀███▄ ▄▀▀▀        ▄▄███▌                                
███████▄      ▀▀█▄       ▄▄██████▀                                 
▐█████████▄       ▀▀▄▄▄█████████▀                                  
 ▀▀▀█████████▄   ▄▄████▀▀▀▀▀▀                                      
      ▀▀▀▀██████▌                                                  
            ▀▀▀▀██▄▄                                               

</p>'''

    print_formatted_text(HTML(pinecone_logo))

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--database', required=False)
    args = parser.parse_args()

    init_database(args)
    print()

    sys.argv = sys.argv[:1]
    Pinecone.load_modules()
    Pinecone().cmdloop()

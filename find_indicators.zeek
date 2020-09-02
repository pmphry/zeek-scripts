# This script is for loading threat intel indicator files into Zeek's 
# Intel framework, from a specified directory, on the fly.  To use it, 
# aside from loading it (@load directive), you should first modify or redef the 
# indicator_dir constant. indicator_dir defines the directory that will 
# be searched for new intel files.  
# 
# This is sort of an untraditional way of getting Intel into Zeek.  Its 
# usually enough to manage a set of statically defined files, and append 
# new indicators to them as they are available.  But there are edge cases, 
# situations where you may not know the name of the intel files ahead 
# of time, or when they will appear.  Maybe they are being generated 
# by another person/team or another process.  Having to manually change 
# the Intel::read_files variable and restarting Zeek is less than ideal in 
# these cases.    
#
# So the idea is to check this specified directory on a set interval. When 
# a new file is found, 'attempt' to load it as a Zeek indicator file.  This 
# assumes of course you're only putting intel files in the directory you 
# define. If Zeek finds a file it can't parse and load as Intel it will 
# complain in reporter.log, so keep an eye on that for problems.  The good 
# news is a new, poorly formatted intel file, won't have any affect on the 
# reading of files that have already been added.   

# Only need to do this on the manager 
@if ( Cluster::local_node_type() == Cluster::MANAGER )

@load base/frameworks/intel
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

module find_indicators;

export {
    # Directory where indicator files are stored 
    const indicator_dir = "/path/to/indicators" &redef;

    # Redef this const to specify which indicator files should be auto-loaded
    # This is really only useful for testing. 
    const autoload_wl: set[string] &redef;

    # Redef this const to specify which indicator files should not be auto-loaded
    # This is also useful for testing, or if for some reason, you must have 
    # non-indicator files in the same directory. 
    const autoload_bl: set[string] &redef;

    # This is the time we wait before checking for new intel files.  Set this
    # based on your needs. If you don't expect new intel to show up frequently
    # set this to a longer interval.   
    const file_check_interval: interval = 10sec &redef;

    # Event triggered when new indicators are read from a file.
    global read_intel: event(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item);
}
# Var for triggering exit on ls failure 
global exit_on_fail = F;

# For keeping track of loaded indicator files 
global loaded_files: set[string];

# Event for inserting indicators into the Intel table 
event read_intel(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item)
    {
    Intel::insert(item); 
    }

# Event for finding and loading indicator files 
event find_indicators()
  {
  # In leiue of a better option, use Exec to run ls on the specified directory.  

  # Create the ls command string using the indicator_dir
  local ls_cmd = Exec::Command($cmd=fmt("ls %s", indicator_dir));

  # Run the ls command asynchronously 
  when (local res = Exec::run(ls_cmd)) 
    {
    # If there was a problem running ls, like the directory doesn't exist, 
    # we don't want to go any further, or keep trying. 
    if ( res?$stderr && |res$stderr| > 0 )
      {
      Reporter::error(fmt("Error running ls: %s", res$stderr));
      exit_on_fail = T;
      return;
      }  
    else if ( res?$stdout )
      {
      # Iterate over the results and attempt to load discovered files as intel. 
      for ( f in res$stdout ) 
        {
        # If the wl is not used all files will be loaded, unless
        # they are specified in the bl.  The bl is applied last
        # so it overrides anything also specified in the wl.  

        # If the wl is in use skip if this file is not listed
        if ( |autoload_wl| > 0 && res$stdout[f] !in autoload_wl )
            {
            next;            
            }

        # If the bl is in use skip if this file if it is listed
        if ( |autoload_bl| > 0 && res$stdout[f] in autoload_bl ) 
            {
            next;
            }

        # Build the absolute path to the indicator file 
        local ifile_path = indicator_dir + "/" + res$stdout[f];

        # Skip if the file has already been added to the Intel framework's
        # read_files variable.  
        if ( ifile_path in Intel::read_files ) 
            {
            next;
            }

        # If we haven't seen and loaded the file before, try now. 
        if ( ifile_path !in loaded_files )
          {        
          Reporter::info(fmt("Adding intel source: %s", ifile_path));

          # Attempt to add the file as an event source
          local add_res = Input::add_event([$source=ifile_path,
                           $reader=Input::READER_ASCII,
                           $mode=Input::STREAM,
                           $name=res$stdout[f],
                           $fields=Intel::Item,
                           $ev=find_indicators::read_intel]);  
          if ( add_res )
            {
            # Add intel file to list of loaded files
            add loaded_files[ifile_path];
            }
          else 
            {
            Reporter::warning(fmt("Unable to add intel source: %s", res$stdout[f]));  
            }
          }
        }
      }
    }  
  # Stop trying if there was an error reading the directory 
  if ( exit_on_fail )
      {
      Reporter::error("Unable to load new indicator files. Exiting...");
      return;
      }  
  
  # Otherwise, schedule the next run of this event handler 
  schedule file_check_interval { find_indicators() };
  }

event zeek_init()
    {
    #  Start the event loop 
    event find_indicators();
    }
@endif
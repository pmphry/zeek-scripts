# Only need to do this on the manager 
@if ( Cluster::local_node_type() == Cluster::MANAGER )

@load base/frameworks/intel
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

module find_indicators;

export {
    # Directory where indicator files are stored 
    global indicator_dir = "/home/ap/zeek/indicators";

    # Redef this const to specify which indicator files should be auto-loaded
    const autoload_wl: set[string] &redef;

    # Redef this const to specify which indicator files should not be auto-loaded
    const autoload_bl: set[string] &redef;

    # Time between intel file checks.  Zeek will will check the indicator_dir for 
    # new files every file_check_interval.  
    const file_check_interval: interval = 10sec &redef;

    # Event triggered when new indicators are read  
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
  # Create the ls command string based on the indicator_dir
  local ls_cmd = Exec::Command($cmd=fmt("ls %s", indicator_dir));

  # Run the ls command asynchronously 
  when (local res = Exec::run(ls_cmd)) 
    {
    if ( res?$stderr && |res$stderr| > 0 )
      {
      Reporter::error(fmt("Error running ls: %s", res$stderr));
      exit_on_fail = T;
      return;
      }  
    else if ( res?$stdout )
      {
      # Attempt to load discovered files as intel 
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

        # If the bl is in use skip if this file is listed
        if ( |autoload_bl| > 0 && res$stdout[f] in autoload_bl ) 
            {
            next;
            }

        local ifile_path = indicator_dir + "/" + res$stdout[f];

        # Skip if the file has already been added to the Intel framework 
        if ( ifile_path in Intel::read_files ) 
            {
            next;
            }

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
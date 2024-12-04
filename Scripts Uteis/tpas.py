import angr
import sys

def main(argv):
    path_to_binary = argv[1]
    
    # Create the angr project for the binary
    project = angr.Project(path_to_binary)
    
    # Create the initial state of the program
    # Add the option to handle uninitialized memory with zeroes
    initial_state = project.factory.entry_state(add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY})
    
    # Create the simulation manager
    simulation = project.factory.simgr(initial_state)

    # Define the success condition: Check if the state prints "Correct!"
    def is_successful(state):
        stdout_output = state.posix.dumps(1)  # 1 is the file descriptor for stdout
        return b'Correct!' in stdout_output

    # Define the abort condition: Avoid states that print "Wrong..."
    def should_abort(state):
        stdout_output = state.posix.dumps(1)
        return b'Wrong...' in stdout_output

    # Explore the binary, looking for the success state and avoiding the failure state
    simulation.explore(find=is_successful, avoid=should_abort)

    # Check if a solution was found
    if simulation.found:
        solution_state = simulation.found[0]
        # Print the input that leads to the "Correct!" message
        print("Solution found:", solution_state.posix.dumps(0))  # 0 is the file descriptor for stdin
    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 symbolic_execution.py <path_to_binary>")
        sys.exit(1)
    
    main(sys.argv)

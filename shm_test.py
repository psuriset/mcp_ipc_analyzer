import sysv_ipc
import sys

KEY = 123456

try:
    # Create a shared memory segment
    memory = sysv_ipc.SharedMemory(KEY, sysv_ipc.IPC_CREX)
    print(f"Shared memory created with key {KEY} and id {memory.id}")

    # Attach to the segment (this should trigger the shmat syscall)
    memory.attach()
    print("Attached to shared memory segment.")

    # Write to the memory
    message = b"Hello from shared memory!"
    memory.write(message)
    print(f"Wrote message: {message.decode()}")

    # Detach
    memory.detach()
    print("Detached from shared memory segment.")

    # Remove the segment
    memory.remove()
    print("Shared memory segment removed.")

except sysv_ipc.ExistentialError:
    print(f"Shared memory with key {KEY} already exists. Cleaning up.")
    sysv_ipc.SharedMemory(KEY).remove()
    print("Cleaned up existing segment. Please run the script again.")
    sys.exit(1)
except Exception as e:
    print(f"An error occurred: {e}", file=sys.stderr)
    # In case of error, try to clean up
    try:
        sysv_ipc.SharedMemory(KEY).remove()
    except sysv_ipc.ExistentialError:
        pass # It was likely never created
    sys.exit(1)

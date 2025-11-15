# Network Packet Router Simulation
> A fully functional network router implementation in C supporting ARP resolution, IP forwarding, ICMP error handling, and longest prefix match routing.
A comprehensive implementation of a network router that handles ARP (Address Resolution Protocol), IP packet forwarding, ICMP error messages, and routing table management. This project demonstrates core networking concepts at Layer 2 (Data Link) and Layer 3 (Network) of the OSI model.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Building the Project](#building-the-project)
- [Usage](#usage)
- [Implementation Details](#implementation-details)
- [Design Decisions](#design-decisions)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## 🎯 Overview

This router implementation provides a fully functional network router capable of:

- Processing Ethernet frames and routing IP packets
- Handling ARP requests and replies for MAC address resolution
- Forwarding IP packets with proper TTL decrement and checksum recalculation
- Generating ICMP error messages (Echo Reply, Time Exceeded, Destination Unreachable, Port Unreachable)
- Maintaining an ARP cache with automatic timeout and retry mechanisms
- Performing longest prefix match routing table lookups

## ✨ Features

### Core Functionality

- **ARP Handling**
  - Processes ARP requests and generates appropriate replies
  - Maintains ARP cache with 15-second timeout
  - Implements ARP request retry mechanism (5 attempts with 1-second intervals)
  - Sends ICMP Host Unreachable messages after ARP timeout

- **IP Packet Processing**
  - Validates IP packet headers and checksums
  - Handles packets destined for the router (ICMP Echo Replies)
  - Forwards packets to next-hop routers
  - Decrements TTL and recalculates IP checksum
  - Generates ICMP Time Exceeded messages for TTL=0 packets

- **ICMP Error Generation**
  - Echo Reply (Type 0) for ping requests
  - Time Exceeded (Type 11) for traceroute
  - Destination Unreachable (Type 3) for network/host unreachable
  - Port Unreachable (Type 3, Code 3) for TCP/UDP packets

- **Routing**
  - Longest prefix match algorithm for route selection
  - Supports static routing tables
  - Interface management and validation

## 🏗️ Architecture

The router is implemented as a modular system with clear separation of concerns:

```
┌─────────────────────────────────────────┐
│         sr_main.c (Entry Point)         │
│  - Initialization                        │
│  - Server connection                     │
│  - Main event loop                       │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│      sr_router.c (Core Logic)           │
│  - Packet handling dispatcher           │
│  - ARP packet processing                │
│  - IP packet processing                  │
│  - ICMP message generation              │
└──────┬───────────────────┬──────────────┘
       │                   │
┌──────▼──────┐   ┌────────▼─────────┐
│ sr_arpcache │   │    sr_rt.c       │
│   .c/.h     │   │  (Routing Table) │
│             │   │                  │
│ - ARP cache │   │ - Route lookup   │
│ - Request   │   │ - LPM algorithm │
│   queue     │   │ - Table mgmt     │
│ - Timeouts  │   └──────────────────┘
└─────────────┘
```

## 📁 Project Structure

```
Network-Packet-Router-Simulation/
├── README.md                 # This file
├── Makefile                  # Build configuration
├── .gitignore               # Git ignore rules
├── rtable                   # Default routing table file
├── auth_key                 # Authentication key for VNS server
│
├── core/                    # Core Router Files
│   ├── sr_main.c            # Main entry point and initialization
│   ├── sr_router.c          # Core packet handling logic
│   ├── sr_router.h          # Router data structures and declarations
│   └── sr_protocol.h        # Network protocol definitions (Ethernet, IP, ARP, ICMP)
│
├── arp/                     # ARP Cache Management
│   ├── sr_arpcache.c        # ARP cache implementation
│   └── sr_arpcache.h        # ARP cache data structures
│
├── routing/                 # Routing Table
│   ├── sr_rt.c              # Routing table operations
│   └── sr_rt.h              # Routing table structures
│
├── interface/               # Interface Management
│   ├── sr_if.c              # Interface operations
│   └── sr_if.h              # Interface data structures
│
├── utils/                   # Utilities
│   ├── sr_utils.c           # Helper functions (checksums, printing)
│   ├── sr_utils.h           # Utility function declarations
│   ├── sr_dumper.c          # Packet dumping functionality
│   └── sr_dumper.h          # Dumper declarations
│
├── network/                 # Network Communication
│   ├── sr_vns_comm.c        # VNS server communication
│   └── vnscommand.h         # VNS command definitions
│
└── crypto/                  # Cryptography
    ├── sha1.c               # SHA-1 implementation
    └── sha1.h               # SHA-1 declarations
```

## 🔨 Building the Project

### Prerequisites

- GCC compiler
- GNU Make
- pthread library (usually included with GCC)
- Network libraries (resolv, nsl - platform dependent)

### Build Instructions

1. **Clean previous builds** (optional):
   ```bash
   make clean
   ```

2. **Build the router**:
   ```bash
   make
   ```

3. **Build with Purify** (optional, for memory debugging):
   ```bash
   make sr.purify
   ```

The build process will:
- Compile all `.c` files into object files (`.o`)
- Generate dependency files (`.d`)
- Link everything into the `sr` executable

### Supported Platforms

The Makefile supports multiple platforms:
- **Linux** (`_LINUX_`)
- **macOS/Darwin** (`_DARWIN_`)
- **Solaris** (`_SOLARIS_`)
- **Cygwin** (`_CYGWIN_`)

## 🚀 Usage

### Basic Usage

```bash
./sr [-h] [-v host] [-s server] [-p port] [-T template_name] [-u username] 
     [-t topo_id] [-r routing_table] [-l log_file]
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-h` | Display help message | - |
| `-v host` | Virtual host name | `vrhost` |
| `-s server` | VNS server address | `localhost` |
| `-p port` | Server port number | `8888` |
| `-T template` | Topology template name | - |
| `-u username` | Username for authentication | (system username) |
| `-t topo_id` | Topology ID | `0` |
| `-r rtable` | Routing table file path | `rtable` |
| `-l logfile` | Packet dump log file | - |

### Example Commands

```bash
# Connect to default server with default routing table
./sr

# Connect to specific server with custom routing table
./sr -s myserver.com -r my_rtable

# Enable packet logging
./sr -l packets.dump

# Use specific topology template
./sr -T my_template -r rtable.vrhost
```

## 🔍 Implementation Details

### Key Components

#### 1. Packet Processing Pipeline (`sr_router.c`)

The main packet handler follows this flow:

```
Ethernet Frame Received
    ↓
Extract Ethernet Header
    ↓
┌───┴───┐
│ ARP?  │  ──→ Handle ARP Request/Reply
│ IP?   │  ──→ Handle IP Packet
└───────┘
```

**ARP Processing:**
- **Request**: Check if target IP matches router interface → Send ARP reply
- **Reply**: Update ARP cache → Forward queued packets

**IP Processing:**
- Validate checksum and header
- Check if packet is for router → Process ICMP Echo
- Otherwise → Forward packet (decrement TTL, update checksum)

#### 2. ARP Cache Management (`sr_arpcache.c`)

**Cache Structure:**
- Fixed-size array (100 entries) with hash-based lookup
- Request queue for pending ARP resolutions
- Thread-safe operations using mutexes

**Timeout Mechanism:**
- Cache entries expire after 15 seconds
- ARP requests retry every 1 second (max 5 attempts)
- After 5 failed attempts → Send ICMP Host Unreachable

**Helper Functions:**
- `sr_arpcache_lookup()`: Find IP→MAC mapping
- `sr_arpcache_queuereq()`: Queue packet waiting for ARP resolution
- `sr_arpcache_insert()`: Add new mapping and process queued packets
- `sr_arpcache_sweepreqs()`: Periodic cleanup of timed-out requests

#### 3. Routing Table (`sr_rt.c`)

**Longest Prefix Match Algorithm:**
```c
for each route in routing_table:
    if (destination_ip & route.mask) == (route.dest & route.mask):
        if (route.mask > best_match.mask):
            best_match = route
return best_match
```

**Features:**
- Supports multiple routes with different subnet masks
- Always selects the most specific (longest prefix) route
- Validates interface existence

#### 4. ICMP Message Generation

The router generates several types of ICMP messages:

**Echo Reply (Type 0):**
- Generated when router receives ICMP Echo Request
- Swaps source/destination IPs and MACs
- Recalculates checksums

**Time Exceeded (Type 11):**
- Generated when TTL reaches 0 during forwarding
- Includes original IP header + 8 bytes of payload

**Destination Unreachable (Type 3):**
- **Code 0**: Network Unreachable (no route found)
- **Code 1**: Host Unreachable (ARP timeout)
- **Code 3**: Port Unreachable (TCP/UDP to router)

### Helper Functions

#### `find_interface_by_ip()` (`sr_router.c`)
Searches router interfaces to find one matching a given IP address. Used to determine if a packet is destined for the router itself.

#### `send_icmp_reply()` (`sr_router.c`)
Constructs and sends ICMP error messages. Handles different ICMP types and codes, properly setting Ethernet and IP headers.

#### `construct_icmp_error_packet()` / `send_icmp_error_packet()` (`sr_arpcache.c`)
Builds ICMP Host Unreachable messages when ARP resolution fails. Separates packet construction from transmission for better modularity.

## 🎨 Design Decisions

### Modular Architecture

The codebase is organized into logical modules:
- **Router core**: Packet handling and routing decisions
- **ARP cache**: Separate module for ARP operations
- **Routing table**: Isolated routing logic
- **Utilities**: Reusable helper functions

This separation improves:
- **Maintainability**: Changes to one module don't affect others
- **Testability**: Each module can be tested independently
- **Readability**: Clear boundaries between components

### Memory Management

- **Borrowed buffers**: Packet buffers are borrowed (not copied) to avoid unnecessary memory allocation
- **Explicit cleanup**: All allocated memory is properly freed
- **Queue management**: ARP request queue properly manages packet references

### Error Handling

- **Input validation**: All functions validate inputs using assertions
- **Graceful degradation**: Router continues operating even if individual packets fail
- **ICMP error reporting**: Proper error messages sent back to sources

### Thread Safety

- **Mutex protection**: ARP cache operations are protected by mutexes
- **Thread-safe queues**: ARP request queue operations are synchronized

## 🧪 Testing

### Manual Testing

1. **Ping Test**:
   ```bash
   ping <router_interface_ip>
   ```
   Should receive ICMP Echo Replies.

2. **Traceroute Test**:
   ```bash
   traceroute <destination>
   ```
   Should see ICMP Time Exceeded messages.

3. **ARP Test**:
   Monitor ARP cache:
   ```bash
   # Router will print ARP cache on certain events
   ```

### Debugging

Enable debug output by ensuring `_DEBUG_` is defined in the Makefile (already enabled by default).

Debug output includes:
- Packet reception notifications
- ARP cache operations
- Routing decisions
- ICMP message generation

### Common Issues and Solutions

**Issue**: Ping replies not reaching client
- **Solution**: Ensure `ip_src` and `ether_shost` are set from the receiving interface

**Issue**: Traceroute not working
- **Solution**: Generate ICMP Time Exceeded when TTL=1, not just drop the packet

**Issue**: Host Unreachable messages not seen
- **Solution**: Verify ICMP error packet construction includes proper Ethernet and IP headers

## 🐛 Troubleshooting

### Build Issues

**Problem**: `pthread` not found
```bash
# Install pthread development package (Linux)
sudo apt-get install libpthread-stubs0-dev
```

**Problem**: Platform-specific compilation errors
- Check that the correct `ARCH` flag is set in Makefile
- Verify platform detection in Makefile

### Runtime Issues

**Problem**: Cannot connect to VNS server
- Verify server address and port
- Check network connectivity
- Ensure `auth_key` file exists and is valid

**Problem**: Routing table not loading
- Verify `rtable` file exists and is readable
- Check routing table format (destination gateway mask interface)
- Ensure interfaces in routing table match actual interfaces

**Problem**: ARP cache not working
- Check mutex initialization
- Verify thread creation for ARP timeout handler
- Monitor debug output for ARP operations

## 📝 Code Quality

### Code Style

- Consistent naming: `snake_case` for functions and variables
- Clear comments: Functions have descriptive headers
- Modular design: Related functionality grouped together
- Error handling: Input validation and error reporting

### Best Practices

- **Assertions**: Used for debugging and catching programming errors
- **Memory safety**: Proper allocation and deallocation
- **Thread safety**: Mutexes protect shared data structures
- **Protocol compliance**: Follows RFC standards for ARP, IP, and ICMP

## 📚 References

- **RFC 826**: Ethernet Address Resolution Protocol (ARP)
- **RFC 791**: Internet Protocol (IP)
- **RFC 792**: Internet Control Message Protocol (ICMP)
- **RFC 1812**: Requirements for IP Version 4 Routers

## 👤 Author

**Mahendra Bikram Shahi**  
JHED: mshahi2

## 📄 License

This project includes code from multiple sources:
- Original VNS stub code (Stanford University, 2009)
- SHA-1 implementation (Mike D. Schiffman, 1998-2000)
- Utility functions (Roger Liao, 2009)

See individual file headers for specific license information.

## 🙏 Acknowledgments

- Stanford University for the VNS framework
- Original authors of the stub code and utilities
- Network protocol RFC authors

---

**Note**: This router is designed for educational purposes and network simulation. It should not be used in production environments without additional security and performance considerations.

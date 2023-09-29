{
  description = "Solana state proof";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
  };

  outputs = { self, nixpkgs }:
    let
      revCount = self.revCount or 1;
      package_version = "0.1.0-${toString revCount}";

      # Systems supported
      allSystems = [
        "x86_64-linux" # 64-bit Intel/AMD Linux
        "aarch64-linux" # 64-bit ARM Linux
        "x86_64-darwin" # 64-bit Intel macOS
        "aarch64-darwin" # 64-bit ARM macOS
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs allSystems (system: f {
        pkgs = import nixpkgs { inherit system; };
      });


      make_package = pkgs: with pkgs;
        let
          stdenv =  pkgs.llvmPackages_15.stdenv;

          pythonEnv = python3.withPackages (ps: with ps; [ sphinx pydata-sphinx-theme ]);
        in
          stdenv.mkDerivation {
            name = "solana_state_proof";
            src = self;
            dontFixCmake = true;
            env.CXXFLAGS = toString([
              "-fPIC"
            ]);
            env.NIX_CFLAGS_COMPILE = toString([
              "-Wno-unused-but-set-variable"
            ]);
            nativeBuildInputs = [
              cmake
              (pkgs.callPackage ./fmt.nix {}).fmt_6
              protobuf
              c-ares
              boost177
              ragel
              gnutls
              lz4
              pkg-config
              yaml-cpp
              lksctp-tools
              hwloc
              numactl
              libxfs
              libsystemtap
              linuxPackages.perf
              gdb
            ];
            cmakeFlags = [
              "-DCMAKE_BUILD_TYPE=Debug"
              "-DBUILD_SHARED_LIBS=FALSE"
              "-DBUILD_TESTS=TRUE"
              "-DBUILD_WITH_NUMA=FALSE"
              "-DBUILD_WITH_CUDA=FALSE"
              "-DBUILD_WITH_OPENCL=FALSE"
              "-DBUILD_WITH_SANITIZE=FALSE"
              "-DBUILD_WITH_DPDK=FALSE"
              "-DCRYPTO3_HASH_POSEIDON=FALSE"
              "-DBUILD_EXAMPLES=TRUE"
              "-DZK_PLACEHOLDER_PROFILING=TRUE"
              "-DBLUEPRINT_PLACEHOLDER_PROOF_GEN=True"
            ];
          };
    in
      {
        packages = forAllSystems({ pkgs }: {
          solana_state_proof = make_package pkgs;
          default = make_package pkgs;
        });
      };
}

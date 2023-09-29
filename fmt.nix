{ lib
, stdenv
, fetchFromGitHub, fetchpatch
, cmake
, enableShared ? !stdenv.hostPlatform.isStatic
# tests
, mpd
, openimageio
, fcitx5
, spdlog
}:

let
  generic = { version, sha256, patches ? [ ] }:
    stdenv.mkDerivation {
      pname = "fmt";
      inherit version;

      outputs = [ "out" "dev" ];

      src = fetchFromGitHub {
        owner = "fmtlib";
        repo = "fmt";
        rev = version;
        inherit sha256;
      };
      patches = [
        # Fix BC break breaking Kodi
        # https://github.com/xbmc/xbmc/issues/17629
        # https://github.com/fmtlib/fmt/issues/1620
        (fetchpatch {
          url = "https://github.com/fmtlib/fmt/commit/7d01859ef16e6b65bc023ad8bebfedecb088bf81.patch";
          sha256 = "0v8hm5958ih1bmnjr16fsbcmdnq4ykyf6b0hg6dxd5hxd126vnxx";
        })

        # Fix paths in pkg-config file
        # https://github.com/fmtlib/fmt/pull/1657
        (fetchpatch {
          url = "https://github.com/fmtlib/fmt/commit/78f041ab5b40a1145ba686aeb8013e8788b08cd2.patch";
          sha256 = "1hqp96zl9l3qyvsm7pxl6ah8c26z035q2mz2pqhqa0wvzd1klcc6";
        })

        # Fix cmake config paths.
        (fetchpatch {
          url = "https://github.com/fmtlib/fmt/pull/1702.patch";
          sha256 = "18cadqi7nac37ymaz3ykxjqs46rvki396g6qkqwp4k00cmic23y3";
        })
        ./fmt.diff
      ];


      nativeBuildInputs = [ cmake ];

      cmakeFlags = [
        "-DBUILD_SHARED_LIBS=${if enableShared then "ON" else "OFF"}"
      ];

      doCheck = true;

      passthru.tests = {
        inherit mpd openimageio fcitx5 spdlog;
      };

      meta = with lib; {
        description = "Small, safe and fast formatting library";
        longDescription = ''
          fmt (formerly cppformat) is an open-source formatting library. It can be
          used as a fast and safe alternative to printf and IOStreams.
        '';
        homepage = "https://fmt.dev/";
        changelog = "https://github.com/fmtlib/fmt/blob/${version}/ChangeLog.rst";
        downloadPage = "https://github.com/fmtlib/fmt/";
        maintainers = [ maintainers.jdehaas ];
        license = licenses.mit;
        platforms = platforms.all;
      };
    };
in
{
  fmt_6 = generic {
    version = "6.2.1";
    sha256 = "sha256-LGKMl65YGbOdMuGmvVpG+mA8efyD+a5HLqAR/FV31sQ=";
  };
  fmt_8 = generic {
    version = "8.1.1";
    sha256 = "sha256-leb2800CwdZMJRWF5b1Y9ocK0jXpOX/nwo95icDf308=";
  };

  fmt_9 = generic {
    version = "9.1.0";
    sha256 = "sha256-rP6ymyRc7LnKxUXwPpzhHOQvpJkpnRFOt2ctvUNlYI0=";
  };

  fmt_10 = generic {
    version = "10.1.1";
    sha256 = "sha256-H9+1lEaHM12nzXSmo9m8S6527t+97e6necayyjCPm1A=";
  };
}

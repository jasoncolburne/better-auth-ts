using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "main", worker = .betterAuthWorker),
  ],
  sockets = [ ( name = "main", address = "*:8080", http = (), service = "main" ) ]
);

const betterAuthWorker :Workerd.Worker = (
  modules = [
    (name = "server", esModule = embed "dist/test-server.js"),
  ],
  compatibilityDate = "2023-02-28"
);

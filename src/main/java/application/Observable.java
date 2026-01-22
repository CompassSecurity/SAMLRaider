package application;

public interface Observable {
  void addObserver(Observer observer);
  void notifyObservers();
}

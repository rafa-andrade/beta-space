extends Area2D

@export var speed = 150
var difficulty_level = 1

func start(pos, level):
	position = pos
	difficulty_level = level
	
func _process(delta):
	position.y += speed * delta * difficulty_level


func _on_visible_on_screen_notifier_2d_screen_exited():
	queue_free()


func _on_area_entered(area):
	if area.name == "Player":
		queue_free()
		area.shield -= 1
